from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml
from tuntun_core.services.models import fs as fs_module
from tuntun_core.services.models import installer as installer_module
from tuntun_core.services.models.fs import hash_exact_fd
from tuntun_core.services.models.installer import ModelInstaller
from tuntun_core.services.models.registry import (
    ActivatedModel,
    ModelRegistry,
    RuntimeFileReceipt,
    RuntimeModelReceipt,
)

MODEL_ID = "mini-model"
PEER_MODEL_ID = "peer-model"
REVISION = "a" * 40
PEER_REVISION = "c" * 40
PREVIOUS_REVISION = "b" * 40
EXPECTED_BYTES = b"tuntun-governed-model-fixture-v1"
EXPECTED_SHA256 = hashlib.sha256(EXPECTED_BYTES).hexdigest()
MODEL_URL = "https://models.example.test/mini.onnx"


def _descriptor_count() -> int:
    try:
        return len(os.listdir("/dev/fd"))
    except FileNotFoundError:
        return 0


def _entry_document() -> dict[str, Any]:
    return {
        "id": MODEL_ID,
        "revision": REVISION,
        "license": "Apache-2.0",
        "provenance": "local test fixture",
        "redistribution": "allowed",
        "approved_purpose": "Task 10 governance verification",
        "runtime": "onnxruntime",
        "architecture": "fixture",
        "input_contract": "bytes",
        "output_contract": "bytes",
        "benchmark_gate": "tests/security/test_model_governance.py",
        "review_date": "2026-08-30",
        "files": [
            {
                "path": "mini.onnx",
                "size": len(EXPECTED_BYTES),
                "sha256": EXPECTED_SHA256,
                "url": MODEL_URL,
            }
        ],
    }


def _write_yaml(path: Path, document: object) -> None:
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    path.chmod(0o600)


class _ScriptedResponse:
    def __init__(self, fault: str | None) -> None:
        payload = EXPECTED_BYTES
        self.status = 200
        self.headers: dict[str, str] = {"content-length": str(len(payload))}
        if fault in {
            "redirect_to_127_0_0_1",
            "redirect_to_rfc1918",
            "redirect_to_other_https_host",
        }:
            self.status = 302
            self.headers["location"] = "https://127.0.0.1/model"
        elif fault == "content_length_too_large":
            self.headers["content-length"] = str(len(payload) + 1)
        elif fault == "stream_plus_one_byte":
            payload += b"!"
            self.headers.pop("content-length", None)
        elif fault == "stream_truncated":
            payload = payload[:-1]
            self.headers.pop("content-length", None)
        elif fault == "hash_mismatch":
            payload = b"x" * len(payload)
        self._payload = payload
        self._offset = 0
        self._fault = fault

    def read(self, size: int) -> bytes:
        if self._fault in {
            "resolver_hang_past_total_deadline",
            "slow_drip_past_total_deadline",
        }:
            raise TimeoutError("model download total deadline")
        if self._fault == "timeout_after_first_file" and self._offset:
            raise TimeoutError("model download total deadline")
        chunk = self._payload[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk


class ScriptedModelTransport:
    def __init__(self) -> None:
        self.fault: str | None = None
        self.followed_redirects: list[str] = []

    def inject(self, fault: str) -> None:
        allowed = {
            "redirect_to_127_0_0_1",
            "redirect_to_rfc1918",
            "redirect_to_other_https_host",
            "allowlisted_dns_private_answer",
            "content_length_too_large",
            "stream_plus_one_byte",
            "stream_truncated",
            "timeout_after_first_file",
            "hash_mismatch",
            "slow_drip_past_total_deadline",
            "resolver_hang_past_total_deadline",
        }
        if fault not in allowed:
            raise AssertionError(f"unknown network fault: {fault}")
        self.fault = fault

    @contextlib.contextmanager
    def stream_exact(
        self,
        _url: str,
        _allowed_hosts: frozenset[str],
        _deadline: float,
    ) -> Any:
        if self.fault == "allowlisted_dns_private_answer":
            raise PermissionError("model host did not resolve only to public addresses")
        yield _ScriptedResponse(self.fault)


class ScriptedReceiptVerifier:
    def __init__(self, domain: str, key_generation: int, publisher: ScriptedRuntimeAdapter) -> None:
        self.domain = domain
        self.key_generation = key_generation
        self.publisher = publisher
        self._fail = False

    @classmethod
    def current(
        cls,
        *,
        domain: str,
        key_generation: int,
        publisher: ScriptedRuntimeAdapter,
    ) -> ScriptedReceiptVerifier:
        return cls(domain, key_generation, publisher)

    def fail_next(self) -> None:
        self._fail = True

    def require_exact_signed_current(
        self,
        candidate: RuntimeModelReceipt,
        *,
        signature_domain: str,
        model_id: str,
        revision: str,
        files: tuple[tuple[str, int, str], ...],
    ) -> RuntimeModelReceipt:
        observed = tuple((item.path, item.size, item.sha256) for item in candidate.files)
        if (
            self._fail
            or signature_domain != self.domain
            or candidate.signature_domain != self.domain
            or candidate.key_generation != self.key_generation
            or candidate.expires_at <= int(time.time())
            or candidate.model_id != model_id
            or candidate.revision != revision
            or observed != files
            or candidate.signature != "fixture-signature"
        ):
            raise ValueError("receipt rejected")
        self.publisher.publish_verified(candidate)
        return candidate


class ScriptedRuntimeAdapter:
    def __init__(self) -> None:
        self.path_opens: list[Path] = []
        self.open_duplicate_fd_count = 0
        self.abort_calls = 0
        self.published_runtime_count = 0
        self._pending_candidate: RuntimeModelReceipt | None = None
        self.last_loaded_bytes = b""
        self._mutation: str | None = None
        self._failure: str | None = None
        self._use_read_at = False
        self._before_read: Any | None = None

    def use_read_at(self) -> None:
        self._use_read_at = True

    def before_read(self, callback: Any) -> None:
        self._before_read = callback

    def mutate_receipt(self, mutation: str) -> None:
        allowed = {
            "wrong_model",
            "wrong_revision",
            "missing_file",
            "extra_file",
            "reordered_file",
            "wrong_size",
            "wrong_hash",
            "wrong_signature_domain",
            "wrong_key_generation",
            "bad_signature",
            "expired_receipt",
        }
        if mutation not in allowed:
            raise AssertionError(f"unknown receipt mutation: {mutation}")
        self._mutation = mutation

    def fail_at(self, failure: str, verifier: ScriptedReceiptVerifier | None) -> None:
        if failure == "receipt_verifier":
            if verifier is None:
                raise AssertionError("receipt verifier is required")
            verifier.fail_next()
        elif failure in {"load_verified_reader", "finish_model"}:
            self._failure = failure
        else:
            raise AssertionError(f"unknown runtime failure: {failure}")

    def load_verified_reader(
        self, reader: Any, path: str, size: int, sha256: str
    ) -> RuntimeFileReceipt:
        self.open_duplicate_fd_count += 1
        try:
            if self._failure == "load_verified_reader":
                raise RuntimeError("scripted loader failure")
            if self._before_read is not None:
                self._before_read()
            if self._use_read_at:
                chunks: list[bytes] = []
                offset = 0
                while offset < size:
                    chunk = reader.read_at(offset, min(7, size - offset))
                    chunks.append(chunk)
                    offset += len(chunk)
                self.last_loaded_bytes = b"".join(chunks)
            else:
                self.last_loaded_bytes = b"".join(reader.chunks())
            if self._mutation == "wrong_size":
                size += 1
            elif self._mutation == "wrong_hash":
                sha256 = "0" * 64
            return RuntimeFileReceipt(path, size, sha256)
        finally:
            self.open_duplicate_fd_count -= 1

    def finish_model(
        self,
        model_id: str,
        revision: str,
        receipts: tuple[RuntimeFileReceipt, ...],
    ) -> RuntimeModelReceipt:
        if self._failure == "finish_model":
            raise RuntimeError("scripted finish failure")
        mutation = self._mutation
        files = receipts
        if mutation == "wrong_model":
            model_id = "other-model"
        elif mutation == "wrong_revision":
            revision = "c" * 40
        elif mutation == "missing_file":
            files = ()
        elif mutation == "extra_file":
            files += (RuntimeFileReceipt("extra.onnx", 1, "0" * 64),)
        elif mutation == "reordered_file":
            files = (RuntimeFileReceipt("first.onnx", 1, "0" * 64),) + files
        domain = "tuntun.runtime-model-loader-receipt.v1"
        generation = 1
        signature = "fixture-signature"
        expires_at = int(time.time()) + 60
        if mutation == "wrong_signature_domain":
            domain = "other.domain"
        elif mutation == "wrong_key_generation":
            generation = 2
        elif mutation == "bad_signature":
            signature = "invalid"
        elif mutation == "expired_receipt":
            expires_at = int(time.time()) - 1
        loaded_hash = hashlib.sha256(self.last_loaded_bytes).hexdigest()
        candidate = RuntimeModelReceipt(
            domain,
            generation,
            expires_at,
            model_id,
            revision,
            files,
            signature,
            loaded_hash,
        )
        if self._pending_candidate is not None:
            raise AssertionError("scripted runtime already has a pending candidate")
        self._pending_candidate = candidate
        return candidate

    @property
    def pending_runtime_count(self) -> int:
        return int(self._pending_candidate is not None)

    def publish_verified(self, candidate: RuntimeModelReceipt) -> None:
        if self._pending_candidate is not candidate:
            raise AssertionError("scripted runtime candidate is not pending")
        self._pending_candidate = None
        self.published_runtime_count += 1

    def abort_model(
        self,
        _model_id: str,
        _revision: str,
        _receipts: tuple[RuntimeFileReceipt, ...],
    ) -> None:
        self.abort_calls += 1
        self._pending_candidate = None


@dataclass(frozen=True, slots=True)
class InstalledModel:
    registry: ModelRegistry
    model_id: str
    expected_bytes: bytes
    expected_sha256: str
    _case: GovernedModelCase

    def replace_every_named_path_with_attacker_bytes(self) -> None:
        self._case.replace_every_named_path_with_attacker_bytes()


@dataclass(frozen=True, slots=True)
class ActivationRaceResult:
    failed_closed: bool
    loaded_sha256: str | None = None


class GovernedModelCase:
    def __init__(self, base: Path, monkeypatch: pytest.MonkeyPatch, baseline: int) -> None:
        self.base = base
        self.monkeypatch = monkeypatch
        self.manifest = base / "manifest.yaml"
        self.model_root = base / "models"
        self.model_id = MODEL_ID
        self.expected_bytes = EXPECTED_BYTES
        self.expected_sha256 = EXPECTED_SHA256
        self.network = ScriptedModelTransport()
        self.reader_open_expected_modes: list[int] = []
        self.written_inode_identity: tuple[int, int] | None = None
        self._baseline = baseline
        self._write_limit: int | None = None
        self._force_activate = False
        self._activations: list[ActivatedModel] = []
        self._fault: str | None = None

    @classmethod
    def create(cls, base: Path, monkeypatch: pytest.MonkeyPatch) -> GovernedModelCase:
        baseline = _descriptor_count()
        base.mkdir(mode=0o700)
        model_root = base / "models"
        model_root.mkdir(mode=0o700)
        _write_yaml(
            base / "manifest.yaml", {"schema_version": "1.0", "models": [_entry_document()]}
        )
        previous = model_root / MODEL_ID / PREVIOUS_REVISION
        previous.mkdir(parents=True, mode=0o700)
        (model_root / MODEL_ID).chmod(0o700)
        previous_file = previous / "prior.onnx"
        previous_file.write_bytes(b"previous-immutable-revision")
        previous_file.chmod(0o400)
        previous.chmod(0o500)
        case = cls(base, monkeypatch, baseline)
        case._previous_snapshot = (
            previous_file.read_bytes(),
            stat.S_IMODE(previous_file.stat().st_mode),
        )
        original_open = installer_module.open_regular_at

        def observed_open(
            directory: Any,
            name: str,
            flags: int,
            *,
            mode: int = 0o600,
            expected_mode: int | None = None,
        ) -> int:
            if name == "mini.onnx" and flags & os.O_ACCMODE == os.O_RDONLY:
                case.reader_open_expected_modes.append(mode)
            return original_open(directory, name, flags, mode=mode, expected_mode=expected_mode)

        original_activate = ModelRegistry.activate

        def tracked_activate(registry: ModelRegistry, model_id: str) -> ActivatedModel:
            activated = original_activate(registry, model_id)
            if registry._root == case.model_root:
                case._track_activation(activated)
            return activated

        monkeypatch.setattr(installer_module, "open_regular_at", observed_open)
        monkeypatch.setattr(ModelRegistry, "activate", tracked_activate)
        return case

    def _track_activation(self, activated: ActivatedModel) -> None:
        if all(existing is not activated for existing in self._activations):
            self._activations.append(activated)

    @property
    def registry(self) -> ModelRegistry:
        return ModelRegistry.load(self.manifest, model_root=self.model_root)

    def _write_once(self, descriptor: int, data: bytes | memoryview) -> int:
        if self._write_limit is None:
            return os.write(descriptor, data)
        if self._write_limit == 0:
            return 0
        return os.write(descriptor, data[: self._write_limit])

    def _fault_hook(self, point: str) -> None:
        if point == self._fault:
            raise RuntimeError(f"scripted crash at {point}")

    def _installer(self, *, fault_hook: Any | None = None) -> ModelInstaller:
        return ModelInstaller(
            self.registry,
            {"models.example.test"},
            self.network,
            write_once=self._write_once,
            fault_hook=fault_hook or self._fault_hook,
        )

    def install(self) -> ActivatedModel:
        self.reader_open_expected_modes.clear()
        activated = self._installer().install(self.model_id)
        self._track_activation(activated)
        metadata = os.fstat(activated.files[0].fd)
        self.written_inode_identity = (metadata.st_dev, metadata.st_ino)
        return activated

    def install_peer_model(self) -> str:
        document = yaml.safe_load(self.manifest.read_text(encoding="utf-8"))
        peer = _entry_document()
        peer["id"] = PEER_MODEL_ID
        peer["revision"] = PEER_REVISION
        document["models"].append(peer)
        _write_yaml(self.manifest, document)
        activated = self._installer().install(PEER_MODEL_ID)
        activated.close()
        return PEER_MODEL_ID

    def require_write_enabled_publish_source(self) -> None:
        publish = installer_module.atomic_publish_dir_noreplace

        def reject_read_only_source(parent: Any, source: str, target: str) -> None:
            stage = parent.child(source)
            try:
                if stat.S_IMODE(os.fstat(stage.fd).st_mode) != 0o700:
                    raise PermissionError("filesystem rejects renaming a read-only directory")
            finally:
                stage.close()
            publish(parent, source, target)

        self.monkeypatch.setattr(
            installer_module,
            "atomic_publish_dir_noreplace",
            reject_read_only_source,
        )

    def as_installed_model(self) -> InstalledModel:
        return InstalledModel(
            self.registry,
            self.model_id,
            self.expected_bytes,
            self.expected_sha256,
            self,
        )

    def concurrent_view(self) -> ConcurrentModelCase:
        return ConcurrentModelCase(self)

    def mutate_manifest(self, mutation: str) -> None:
        document: dict[str, Any] = {"schema_version": "1.0", "models": [_entry_document()]}
        entry = document["models"][0]
        file = entry["files"][0]
        if mutation == "duplicate_yaml_key":
            self.manifest.write_text("schema_version: '1.0'\nschema_version: '1.0'\nmodels: []\n")
            return
        if mutation == "yaml_alias":
            self.manifest.write_text("schema_version: '1.0'\nmodels: &models []\ncopy: *models\n")
            return
        if mutation == "manifest_too_large":
            self.manifest.write_bytes(b"#" * 1_048_577)
            return
        if mutation == "duplicate_model_id":
            document["models"].append(_entry_document())
        elif mutation == "duplicate_file_name":
            entry["files"].append(dict(file))
        elif mutation == "unknown_top_level":
            document["unknown"] = True
        elif mutation == "unknown_model_field":
            entry["unknown"] = True
        elif mutation == "unknown_file_field":
            file["unknown"] = True
        elif mutation == "bad_model_id":
            entry["id"] = "Bad Model"
        elif mutation == "floating_revision":
            entry["revision"] = "main"
        elif mutation == "uppercase_hash":
            file["sha256"] = EXPECTED_SHA256.upper()
        elif mutation == "zero_size":
            file["size"] = 0
        elif mutation == "file_too_large":
            file["size"] = 4_000_000_001
        elif mutation == "total_too_large":
            entry["files"] = [
                {**dict(file), "path": f"part-{index}.onnx", "size": 4_000_000_000}
                for index in range(3)
            ]
        elif mutation == "nested_path":
            file["path"] = "nested/mini.onnx"
        elif mutation == "dot_path":
            file["path"] = "."
        elif mutation == "pickle_suffix":
            file["path"] = "model.pkl"
        elif mutation == "http_url":
            file["url"] = "http://models.example.test/mini.onnx"
        elif mutation == "ipv6_url":
            file["url"] = "https://[2606:4700:4700::1111]/mini.onnx"
        elif mutation == "uppercase_scheme_url":
            file["url"] = "HTTPS://models.example.test/mini.onnx"
        elif mutation == "url_credentials":
            file["url"] = "https://user:pass@models.example.test/mini.onnx"
        elif mutation == "url_padded_port":
            file["url"] = "https://models.example.test:0443/mini.onnx"
        elif mutation == "url_port":
            file["url"] = "https://models.example.test:444/mini.onnx"
        elif mutation == "url_query":
            file["url"] = "https://models.example.test/mini.onnx?x=1"
        elif mutation == "too_many_models":
            document["models"] = [
                {**_entry_document(), "id": f"model-{index}"} for index in range(257)
            ]
        elif mutation == "too_many_files":
            entry["files"] = [{**dict(file), "path": f"part-{index}.onnx"} for index in range(65)]
        elif mutation == "bool_size":
            file["size"] = True
        elif mutation == "string_size":
            file["size"] = str(len(EXPECTED_BYTES))
        elif mutation == "list_model_id":
            entry["id"] = [MODEL_ID]
        elif mutation == "mapping_revision":
            entry["revision"] = {"value": REVISION}
        elif mutation == "null_url":
            file["url"] = None
        elif mutation == "path_space":
            file["path"] = "model space.onnx"
        elif mutation == "path_too_long":
            file["path"] = f"{'a' * 252}.onnx"
        elif mutation == "url_too_long":
            file["url"] = f"https://models.example.test/{'a' * 4090}.onnx"
        elif mutation == "metadata_too_long":
            entry["provenance"] = "a" * 4097
        else:
            raise AssertionError(f"unknown manifest mutation: {mutation}")
        _write_yaml(self.manifest, document)

    def _revision_path(self) -> Path:
        return self.model_root / self.model_id / REVISION

    def _artifact_path(self) -> Path:
        return self._revision_path() / "mini.onnx"

    @property
    def recovery_marker_path(self) -> Path:
        return self.model_root / self.model_id / f".recovery-pending-{REVISION}"

    @property
    def publication_commit_path(self) -> Path:
        return self.model_root / self.model_id / f".publication-verified-{REVISION}"

    @property
    def recovery_marker_exists(self) -> bool:
        return self.recovery_marker_path.exists()

    def clear_process_publication_uncertainty(self) -> None:
        resolver = getattr(fs_module, "_resolve_publication_uncertainty", None)
        if resolver is None or not (self.model_root / self.model_id).exists():
            return
        model = fs_module.OwnedDirectory.open(self.model_root / self.model_id)
        try:
            resolver(model, REVISION)
        finally:
            model.close()

    def create_interrupted_recovery_marker(self) -> None:
        self.recovery_marker_path.write_bytes(b"")
        self.recovery_marker_path.chmod(0o600)

    def create_sealed_pending_revision(self) -> None:
        self.crash_install_at("after_publish_before_seal")
        self.create_interrupted_recovery_marker()
        model = fs_module.OwnedDirectory.open(self.model_root / self.model_id)
        revision = model.child(REVISION)
        marker_fd = fs_module.open_regular_at(
            model,
            self.recovery_marker_path.name,
            os.O_RDWR,
            mode=0o600,
            expected_mode=0o600,
        )
        try:
            os.fsync(marker_fd)
            model.fsync()
            revision.chmod(0o500)
            revision.fsync()
            model.fsync()
        finally:
            os.close(marker_fd)
            revision.close()
            model.close()

    def apply_filesystem_mutation(self, mutation: str) -> None:
        allowed = {
            "manifest_symlink",
            "model_root_symlink",
            "model_id_symlink",
            "revision_symlink",
            "artifact_symlink",
            "artifact_fifo",
            "artifact_device",
            "unexpected_artifact",
            "wrong_owner",
            "group_writable_root",
            "world_writable_revision",
        }
        if mutation not in allowed:
            raise AssertionError(f"unknown filesystem mutation: {mutation}")
        if mutation == "manifest_symlink":
            target = self.base / "manifest-target.yaml"
            shutil.copyfile(self.manifest, target)
            target.chmod(0o600)
            self.manifest.unlink()
            self.manifest.symlink_to(target)
            return
        activated = self.install()
        activated.close()
        self._activations.remove(activated)
        self._force_activate = True
        root = self.model_root
        model = root / self.model_id
        revision = self._revision_path()
        artifact = self._artifact_path()
        if mutation == "model_root_symlink":
            backup = self.base / "models-backup"
            root.rename(backup)
            root.symlink_to(backup, target_is_directory=True)
        elif mutation == "model_id_symlink":
            backup = root / "model-backup"
            model.rename(backup)
            model.symlink_to(backup, target_is_directory=True)
        elif mutation == "revision_symlink":
            backup = model / "revision-backup"
            revision.rename(backup)
            revision.symlink_to(backup, target_is_directory=True)
        elif mutation in {"artifact_symlink", "artifact_fifo", "artifact_device"}:
            revision.chmod(0o700)
            artifact.unlink()
            if mutation == "artifact_fifo":
                os.mkfifo(artifact, 0o400)
            else:
                artifact.symlink_to("/dev/null")
            revision.chmod(0o500)
        elif mutation == "unexpected_artifact":
            revision.chmod(0o700)
            unexpected = revision / "unexpected.onnx"
            unexpected.write_bytes(b"unexpected")
            unexpected.chmod(0o400)
            revision.chmod(0o500)
        elif mutation == "wrong_owner":
            self.monkeypatch.setattr(fs_module, "_effective_user_id", lambda: os.geteuid() + 1)
        elif mutation == "group_writable_root":
            root.chmod(0o770)
        elif mutation == "world_writable_revision":
            revision.chmod(0o507)

    def registry_or_activate(self) -> object:
        registry = self.registry
        if self._force_activate:
            return registry.activate(self.model_id)
        return registry

    def inject_os_write_result(self, result: int) -> None:
        self._write_limit = result

    def inject_repeated_os_write_result(self, result: int) -> None:
        self._write_limit = result

    @property
    def open_descriptor_count(self) -> int:
        return max(0, _descriptor_count() - self._baseline)

    def final_revision_exists(self) -> bool:
        return self._revision_path().exists()

    @property
    def final_revision_mode(self) -> int | None:
        try:
            return stat.S_IMODE(self._revision_path().stat(follow_symlinks=False).st_mode)
        except FileNotFoundError:
            return None

    def mutate_unsealed_revision(self, mutation: str) -> None:
        revision = self._revision_path()
        artifact = self._artifact_path()
        if mutation == "unexpected_file":
            unexpected = revision / "unexpected.onnx"
            unexpected.write_bytes(b"unexpected")
            unexpected.chmod(0o400)
        elif mutation == "missing_artifact":
            artifact.unlink()
        elif mutation == "hash_mismatch":
            artifact.chmod(0o600)
            artifact.write_bytes(b"x" * len(self.expected_bytes))
            artifact.chmod(0o400)
        elif mutation == "artifact_symlink":
            artifact.unlink()
            artifact.symlink_to("/dev/null")
        elif mutation == "artifact_fifo":
            artifact.unlink()
            os.mkfifo(artifact, 0o400)
        elif mutation == "writable_artifact":
            artifact.chmod(0o600)
        elif mutation == "wrong_size":
            artifact.chmod(0o600)
            artifact.write_bytes(self.expected_bytes + b"!")
            artifact.chmod(0o400)
        else:
            raise AssertionError(f"unknown unsealed revision mutation: {mutation}")

    def restart_with_post_seal_recovery_fault(self, fault: str) -> ActivatedModel:
        if fault not in {"mutate_artifact", "raise_error"}:
            raise AssertionError(f"unknown post-seal recovery fault: {fault}")

        def inject(point: str) -> None:
            if point != "after_recovery_seal_before_verify":
                return
            if fault == "raise_error":
                raise RuntimeError("scripted post-seal recovery failure")
            artifact = self._artifact_path()
            artifact.chmod(0o600)
            artifact.write_bytes(b"x" * len(self.expected_bytes))
            artifact.chmod(0o400)

        activated = self._installer(fault_hook=inject).install(self.model_id)
        self._track_activation(activated)
        return activated

    def final_revision_is_complete_and_verified(self) -> bool:
        try:
            activated = self.registry.activate(self.model_id)
        except RuntimeError:
            return False
        try:
            return activated.all_files_verified
        finally:
            activated.close()

    def returned_descriptor_identity(self, descriptor: int) -> tuple[int, int]:
        identity = os.fstat(descriptor)
        return identity.st_dev, identity.st_ino

    def rehash_exact_descriptor(self, descriptor: int) -> None:
        hash_exact_fd(descriptor, len(self.expected_bytes), self.expected_sha256)

    def replace_every_named_path_with_attacker_bytes(self) -> None:
        revision = self._revision_path()
        artifact = self._artifact_path()
        revision.chmod(0o700)
        artifact.unlink()
        artifact.write_bytes(b"attacker-bytes")
        artifact.chmod(0o400)
        revision.chmod(0o500)

    def previous_revision_unchanged(self) -> bool:
        path = self.model_root / self.model_id / PREVIOUS_REVISION / "prior.onnx"
        return (
            path.exists()
            and (
                path.read_bytes(),
                stat.S_IMODE(path.stat().st_mode),
            )
            == self._previous_snapshot
        )

    def race_activation(
        self, race: str, runtime_adapter: ScriptedRuntimeAdapter
    ) -> ActivationRaceResult:
        allowed = {
            "swap_root_before_open",
            "swap_revision_during_open",
            "swap_file_during_open",
            "grow_file_during_hash",
            "truncate_file_during_hash",
            "overwrite_same_size_during_load",
        }
        if race not in allowed:
            raise AssertionError(f"unknown activation race: {race}")
        activated = self.install()
        if race == "overwrite_same_size_during_load":
            revision = self._revision_path()
            artifact = self._artifact_path()
            revision.chmod(0o700)
            artifact.chmod(0o600)
            writer = os.open(artifact, os.O_WRONLY)
            artifact.chmod(0o400)
            revision.chmod(0o500)
            attacker = b"x" * len(self.expected_bytes)
            runtime_adapter.before_read(lambda: os.pwrite(writer, attacker, 0))
            verifier = ScriptedReceiptVerifier.current(
                domain="tuntun.runtime-model-loader-receipt.v1",
                key_generation=1,
                publisher=runtime_adapter,
            )
            try:
                receipt = activated.load_with(runtime_adapter, verifier)
            except PermissionError:
                return ActivationRaceResult(True)
            finally:
                os.close(writer)
            return ActivationRaceResult(False, receipt.loaded_sha256)
        activated.close()
        self._activations.remove(activated)
        revision = self._revision_path()
        artifact = self._artifact_path()
        if race == "swap_root_before_open":
            backup = self.base / "race-root"
            self.model_root.rename(backup)
            self.model_root.symlink_to(backup, target_is_directory=True)
        elif race == "swap_revision_during_open":
            backup = revision.parent / "race-revision"
            revision.rename(backup)
            revision.symlink_to(backup, target_is_directory=True)
        else:
            revision.chmod(0o700)
            if race == "grow_file_during_hash":
                artifact.chmod(0o600)
                with artifact.open("ab") as stream:
                    stream.write(b"!")
                artifact.chmod(0o400)
            elif race == "truncate_file_during_hash":
                artifact.chmod(0o600)
                with artifact.open("r+b") as stream:
                    stream.truncate(1)
                artifact.chmod(0o400)
            else:
                artifact.unlink()
                artifact.symlink_to("/dev/null")
            revision.chmod(0o500)
        try:
            candidate = self.registry.activate(self.model_id)
        except (PermissionError, RuntimeError, ValueError):
            return ActivationRaceResult(True)
        candidate.close()
        return ActivationRaceResult(False, self.expected_sha256)

    def crash_install_at(self, fault: str) -> None:
        allowed = {
            "after_each_file",
            "before_stage_fsync",
            "after_stage_fsync",
            "before_publish",
            "after_publish_before_seal",
            "after_publish_before_parent_fsync",
        }
        if fault not in allowed:
            raise AssertionError(f"unknown crash point: {fault}")
        self._fault = fault
        try:
            self.install()
        except RuntimeError:
            pass
        finally:
            self._fault = None

    def restart_and_reconcile(self) -> None:
        activated = self.install()
        activated.close()
        self._activations.remove(activated)

    def final_revision_is_absent_or_complete_and_verified(self) -> bool:
        return not self.final_revision_exists() or self.final_revision_is_complete_and_verified()

    def close(self) -> None:
        for activated in self._activations:
            activated.close()
        self._activations.clear()
        if self.open_descriptor_count != 0:
            raise AssertionError("model-governance fixture leaked a descriptor")
        if not self.base.exists():
            return
        for root, directories, files in os.walk(self.base, topdown=False, followlinks=False):
            root_path = Path(root)
            root_path.chmod(0o700)
            for name in files:
                path = root_path / name
                identity = path.lstat()
                if stat.S_ISREG(identity.st_mode):
                    path.chmod(0o600)
                else:
                    path.unlink()
            for name in directories:
                path = root_path / name
                if path.is_symlink():
                    path.unlink()
                else:
                    path.chmod(0o700)
        shutil.rmtree(self.base)


class _LockProbe:
    def __init__(self) -> None:
        self.current = 0
        self.maximum = 0
        self._lock = threading.Lock()

    def __call__(self, point: str) -> None:
        if point != "after_each_file":
            return
        with self._lock:
            self.current += 1
            self.maximum = max(self.maximum, self.current)
        time.sleep(0.03)
        with self._lock:
            self.current -= 1


class ConcurrentModelCase:
    def __init__(self, case: GovernedModelCase) -> None:
        self.case = case
        self.maximum_simultaneous_lock_holders = 0
        self.published_revision_count = 0

    def run_two_installers(self) -> tuple[ActivatedModel, ...]:
        probe = _LockProbe()
        barrier = threading.Barrier(2)
        results: list[ActivatedModel] = []
        failures: list[BaseException] = []
        result_lock = threading.Lock()

        def run() -> None:
            try:
                installer = ModelInstaller(
                    self.case.registry,
                    {"models.example.test"},
                    self.case.network,
                    write_once=self.case._write_once,
                    fault_hook=probe,
                )
                barrier.wait(timeout=2)
                result = installer.install(MODEL_ID)
                with result_lock:
                    results.append(result)
            except BaseException as error:
                with result_lock:
                    failures.append(error)

        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        if any(thread.is_alive() for thread in threads):
            raise AssertionError("concurrent installer did not terminate")
        if failures:
            raise failures[0]
        for result in results:
            self.case._track_activation(result)
        self.maximum_simultaneous_lock_holders = probe.maximum
        model_dir = self.case.model_root / MODEL_ID
        self.published_revision_count = sum(
            child.name == REVISION and child.is_dir() for child in model_dir.iterdir()
        )
        return tuple(results)

    def no_stage_directory_remains(self) -> bool:
        model_dir = self.case.model_root / MODEL_ID
        return not any(child.name.startswith(".stage-") for child in model_dir.iterdir())


__all__ = [
    "ConcurrentModelCase",
    "GovernedModelCase",
    "InstalledModel",
    "ScriptedReceiptVerifier",
    "ScriptedRuntimeAdapter",
]
