from __future__ import annotations

import contextlib
import fcntl
import inspect
import os
import socket
import stat
import subprocess
import sys
import threading
import time
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from tuntun_core.cli.commands import models as models_command
from tuntun_core.cli.main import app
from tuntun_core.services.models import fs as fs_module
from tuntun_core.services.models import installer as installer_module
from tuntun_core.services.models import network as network_module
from tuntun_core.services.models import registry as registry_module
from tuntun_core.services.models.fs import OwnedDirectory, hash_exact_fd
from tuntun_core.services.models.installer import ModelInstaller
from tuntun_core.services.models.registry import (
    ModelRegistry,
    ModelVerificationError,
    VerifiedModelFile,
)
from typer.testing import CliRunner


def test_floating_revision_and_pickle_are_rejected(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        'schema_version: "1.0"\nmodels:\n- id: bad\n  revision: main\n'
        '  files:\n  - path: model.pkl\n    size: 1\n    sha256: "' + "0" * 64 + '"\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="invalid model manifest"):
        ModelRegistry.load(manifest)


def test_empty_registry_never_downloads(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text('schema_version: "1.0"\nmodels: []\n', encoding="utf-8")
    registry = ModelRegistry.load(manifest)
    with pytest.raises(LookupError, match="model is not registered"):
        registry.activate("missing")


def test_fifo_manifest_is_rejected_without_blocking(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.yaml"
    ready = tmp_path / "child-ready"
    os.mkfifo(manifest, 0o600)
    program = (
        "from pathlib import Path\n"
        "from tuntun_core.services.models.registry import ModelRegistry\n"
        "Path(__import__('sys').argv[2]).write_text('ready', encoding='utf-8')\n"
        "try:\n"
        "    ModelRegistry.load(Path(__import__('sys').argv[1]))\n"
        "except ValueError:\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(1)\n"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", program, str(manifest), str(ready)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        startup_deadline = time.monotonic() + 10
        while not ready.exists():
            if process.poll() is not None:
                _stdout, stderr = process.communicate()
                pytest.fail(f"manifest child exited before readiness: {stderr}")
            if time.monotonic() >= startup_deadline:
                pytest.fail("manifest child startup timed out")
            time.sleep(0.01)
        try:
            _stdout, stderr = process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            pytest.fail("FIFO manifest read blocked after child readiness")
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
    assert process.returncode == 0, stderr


@pytest.mark.parametrize(
    "mutation",
    (
        "duplicate_yaml_key",
        "yaml_alias",
        "manifest_too_large",
        "duplicate_model_id",
        "duplicate_file_name",
        "unknown_top_level",
        "unknown_model_field",
        "unknown_file_field",
        "bad_model_id",
        "floating_revision",
        "uppercase_hash",
        "zero_size",
        "file_too_large",
        "total_too_large",
        "nested_path",
        "dot_path",
        "pickle_suffix",
        "http_url",
        "ipv6_url",
        "uppercase_scheme_url",
        "url_credentials",
        "url_padded_port",
        "url_port",
        "url_query",
        "too_many_models",
        "too_many_files",
        "bool_size",
        "string_size",
        "list_model_id",
        "mapping_revision",
        "null_url",
        "path_space",
        "path_too_long",
        "url_too_long",
        "metadata_too_long",
    ),
)
def test_manifest_runtime_checks_reject_even_without_json_schema(
    governed_model_case: object,
    mutation: str,
) -> None:
    case = governed_model_case
    case.mutate_manifest(mutation)  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="invalid model manifest"):
        ModelRegistry.load(case.manifest)  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "mutation",
    (
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
    ),
)
def test_every_named_filesystem_object_is_nofollow_regular_owner_only(
    governed_model_case: object,
    mutation: str,
) -> None:
    case = governed_model_case
    case.apply_filesystem_mutation(mutation)  # type: ignore[attr-defined]
    with pytest.raises(
        (PermissionError, RuntimeError, ValueError),
        match="unsafe model filesystem|invalid model manifest|not installed and verified",
    ):
        case.registry_or_activate()  # type: ignore[attr-defined]


def test_activation_and_runtime_use_the_same_descriptor_not_a_reopened_path(
    installed_model: object,
    runtime_adapter: object,
    runtime_receipt_verifier: object,
) -> None:
    activated = installed_model.registry.activate(installed_model.model_id)  # type: ignore[attr-defined]
    installed_model.replace_every_named_path_with_attacker_bytes()  # type: ignore[attr-defined]
    receipt = activated.load_with(runtime_adapter, runtime_receipt_verifier)
    assert receipt.loaded_sha256 == installed_model.expected_sha256  # type: ignore[attr-defined]
    assert runtime_adapter.path_opens == []  # type: ignore[attr-defined]
    assert runtime_adapter.pending_runtime_count == 0  # type: ignore[attr-defined]
    assert runtime_adapter.published_runtime_count == 1  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "mutation",
    (
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
    ),
)
def test_runtime_loader_receipt_is_authenticated_and_exact_bound(
    installed_model: object,
    runtime_adapter: object,
    runtime_receipt_verifier: object,
    mutation: str,
) -> None:
    runtime_adapter.mutate_receipt(mutation)  # type: ignore[attr-defined]
    activated = installed_model.registry.activate(installed_model.model_id)  # type: ignore[attr-defined]
    with pytest.raises(ModelVerificationError, match="runtime model receipt mismatch"):
        activated.load_with(runtime_adapter, runtime_receipt_verifier)
    assert runtime_adapter.open_duplicate_fd_count == 0  # type: ignore[attr-defined]
    assert runtime_adapter.abort_calls == 1  # type: ignore[attr-defined]


def test_zero_write_fails_without_publishing(governed_model_case: object) -> None:
    governed_model_case.inject_os_write_result(0)  # type: ignore[attr-defined]
    with pytest.raises(OSError):
        governed_model_case.install()  # type: ignore[attr-defined]
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]
    assert not governed_model_case.final_revision_exists()  # type: ignore[attr-defined]


def test_repeated_one_byte_short_writes_eventually_publish_exact_bytes(
    governed_model_case: object,
) -> None:
    governed_model_case.inject_repeated_os_write_result(1)  # type: ignore[attr-defined]
    result = governed_model_case.install()  # type: ignore[attr-defined]
    assert result.all_files_verified
    assert governed_model_case.final_revision_is_complete_and_verified()  # type: ignore[attr-defined]


def test_installer_retains_only_same_inode_read_only_verified_descriptor(
    governed_model_case: object,
    runtime_adapter: object,
    runtime_receipt_verifier: object,
) -> None:
    activated = governed_model_case.install()  # type: ignore[attr-defined]
    handle = activated.files[0]
    assert governed_model_case.reader_open_expected_modes == [0o600]  # type: ignore[attr-defined]
    assert fcntl.fcntl(handle.fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
    assert stat.S_IMODE(os.fstat(handle.fd).st_mode) == 0o400
    assert (
        governed_model_case.returned_descriptor_identity(handle.fd)  # type: ignore[attr-defined]
        == governed_model_case.written_inode_identity  # type: ignore[attr-defined]
    )
    governed_model_case.rehash_exact_descriptor(handle.fd)  # type: ignore[attr-defined]
    with pytest.raises(OSError):
        os.write(handle.fd, b"mutation")
    receipt = activated.load_with(runtime_adapter, runtime_receipt_verifier)
    assert receipt.loaded_sha256 == governed_model_case.expected_sha256  # type: ignore[attr-defined]
    source = inspect.getsource(ModelInstaller._download)
    assert "return read_fd" in source
    assert "return write_fd" not in source and "return fd" not in source
    assert runtime_adapter.path_opens == []  # type: ignore[attr-defined]


def test_fresh_install_wrapper_failure_closes_download_descriptor_once(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    retained_descriptor: list[int] = []
    close_attempts: list[int] = []
    real_close = os.close

    def fail_from_manifest(
        _cls: type[VerifiedModelFile], _item: object, descriptor: int
    ) -> VerifiedModelFile:
        retained_descriptor.append(descriptor)
        raise RuntimeError("scripted wrapper construction failure")

    def track_close(descriptor: int) -> None:
        if retained_descriptor and descriptor == retained_descriptor[0]:
            close_attempts.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(
        VerifiedModelFile,
        "from_manifest",
        classmethod(fail_from_manifest),
    )
    monkeypatch.setattr(os, "close", track_close)

    with pytest.raises(RuntimeError, match="scripted wrapper construction failure"):
        governed_model_case.install()  # type: ignore[attr-defined]

    assert len(retained_descriptor) == 1
    assert close_attempts == retained_descriptor
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


def test_fresh_install_raw_cleanup_failure_preserves_wrapper_error(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = RuntimeError("scripted wrapper construction failure")
    retained_descriptor: list[int] = []
    close_attempts: list[int] = []
    real_close = os.close

    def fail_from_manifest(
        _cls: type[VerifiedModelFile], _item: object, descriptor: int
    ) -> VerifiedModelFile:
        retained_descriptor.append(descriptor)
        raise primary

    def fail_retained_close(descriptor: int) -> None:
        if retained_descriptor and descriptor == retained_descriptor[0]:
            close_attempts.append(descriptor)
            real_close(descriptor)
            raise OSError("scripted retained descriptor close failure")
        real_close(descriptor)

    monkeypatch.setattr(
        VerifiedModelFile,
        "from_manifest",
        classmethod(fail_from_manifest),
    )
    monkeypatch.setattr(os, "close", fail_retained_close)

    with pytest.raises(RuntimeError) as caught:
        governed_model_case.install()  # type: ignore[attr-defined]

    assert caught.value is primary
    assert caught.value.__notes__ == ["additional descriptor cleanup failure"]
    assert close_attempts == retained_descriptor
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


def test_fresh_install_wrapper_cleanup_failure_preserves_transfer_error(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = RuntimeError("scripted downloaded wrapper transfer failure")
    retained_handle: list[VerifiedModelFile] = []
    close_attempts: list[int] = []
    real_from_manifest = VerifiedModelFile.from_manifest
    real_close = VerifiedModelFile.close

    def capture_from_manifest(
        _cls: type[VerifiedModelFile], item: object, descriptor: int
    ) -> VerifiedModelFile:
        handle = real_from_manifest(item, descriptor)  # type: ignore[arg-type]
        retained_handle.append(handle)
        return handle

    def fail_transfer(point: str) -> None:
        if point == "before_retain_downloaded_file":
            raise primary

    def fail_handle_close(handle: VerifiedModelFile) -> None:
        if retained_handle and handle is retained_handle[0]:
            close_attempts.append(id(handle))
            real_close(handle)
            raise OSError("scripted downloaded wrapper close failure")
        real_close(handle)

    monkeypatch.setattr(
        VerifiedModelFile,
        "from_manifest",
        classmethod(capture_from_manifest),
    )
    monkeypatch.setattr(VerifiedModelFile, "close", fail_handle_close)

    caught: RuntimeError | None = None
    try:
        activated = governed_model_case._installer(  # type: ignore[attr-defined]
            fault_hook=fail_transfer
        ).install(governed_model_case.model_id)  # type: ignore[attr-defined]
    except RuntimeError as error:
        caught = error
    else:
        activated.close()

    assert caught is primary
    assert caught.__notes__ == ["additional descriptor cleanup failure"]
    assert close_attempts == [id(retained_handle[0])]
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


def test_download_write_descriptor_close_failure_is_not_retried(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_descriptors: list[int] = []
    close_attempts: list[int] = []
    real_open = installer_module.open_regular_at
    real_close = os.close

    def capture_open(
        directory: object,
        name: str,
        flags: int,
        *,
        mode: int = 0o600,
        expected_mode: int | None = None,
    ) -> int:
        descriptor = real_open(  # type: ignore[arg-type]
            directory,
            name,
            flags,
            mode=mode,
            expected_mode=expected_mode,
        )
        if flags & os.O_ACCMODE == os.O_WRONLY:
            write_descriptors.append(descriptor)
        return descriptor

    def fail_first_write_close(descriptor: int) -> None:
        if write_descriptors and descriptor == write_descriptors[0]:
            try:
                os.fstat(descriptor)
            except OSError:
                close_attempts.append(descriptor)
                real_close(descriptor)
                return
            if not close_attempts:
                close_attempts.append(descriptor)
                real_close(descriptor)
                raise OSError("scripted write descriptor close failure")
        real_close(descriptor)

    monkeypatch.setattr(installer_module, "open_regular_at", capture_open)
    monkeypatch.setattr(os, "close", fail_first_write_close)

    with pytest.raises(OSError, match="scripted write descriptor close failure"):
        governed_model_case.install()  # type: ignore[attr-defined]

    assert len(write_descriptors) == 1
    assert close_attempts == write_descriptors
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


def test_activated_manifest_expectations_and_file_tuple_cannot_be_rebased(
    installed_model: object,
    tmp_path: Path,
) -> None:
    activated = installed_model.registry.activate(installed_model.model_id)  # type: ignore[attr-defined]
    handle = activated.files[0]
    attacker = tmp_path / "attacker.onnx"
    attacker.write_bytes(b"attacker-bytes")
    attacker.chmod(0o400)
    attacker_fd = os.open(attacker, os.O_RDONLY)
    try:
        for attribute, value in (
            ("fd", attacker_fd),
            ("size", os.fstat(attacker_fd).st_size),
            ("sha256", "0" * 64),
        ):
            with pytest.raises((FrozenInstanceError, AttributeError)):
                setattr(handle, attribute, value)
        with pytest.raises((FrozenInstanceError, AttributeError)):
            activated.files = (handle,)
        assert activated.all_files_verified is True
    finally:
        os.close(attacker_fd)


@pytest.mark.parametrize("prior_offset", (0, 1, "eof"))
def test_rehash_and_repeated_runtime_reads_ignore_shared_descriptor_offset(
    installed_model: object,
    runtime_adapter: object,
    prior_offset: int | str,
) -> None:
    handle = installed_model.registry.activate(installed_model.model_id).files[0]  # type: ignore[attr-defined]
    offset = handle.size if prior_offset == "eof" else prior_offset
    os.lseek(handle.fd, offset, os.SEEK_SET)
    for _ in range(2):
        hash_exact_fd(handle.fd, handle.size, handle.sha256)
        assert os.lseek(handle.fd, 0, os.SEEK_CUR) == offset
        handle.load_with(runtime_adapter)
        assert runtime_adapter.last_loaded_bytes == installed_model.expected_bytes  # type: ignore[attr-defined]
        assert os.lseek(handle.fd, 0, os.SEEK_CUR) == offset


def test_runtime_reader_supports_exact_sequential_pread(
    installed_model: object,
    runtime_adapter: object,
    runtime_receipt_verifier: object,
) -> None:
    runtime_adapter.use_read_at()  # type: ignore[attr-defined]
    activated = installed_model.registry.activate(installed_model.model_id)  # type: ignore[attr-defined]
    receipt = activated.load_with(runtime_adapter, runtime_receipt_verifier)
    assert receipt.loaded_sha256 == installed_model.expected_sha256  # type: ignore[attr-defined]


def test_activated_model_close_is_idempotent_and_cannot_close_reused_fd(
    installed_model: object,
    runtime_adapter: object,
    runtime_receipt_verifier: object,
    tmp_path: Path,
) -> None:
    activated = installed_model.registry.activate(installed_model.model_id)  # type: ignore[attr-defined]
    released_fd = activated.files[0].fd
    activated.close()
    replacement = tmp_path / "replacement.txt"
    replacement.write_text("still open", encoding="utf-8")
    replacements: list[int] = []
    try:
        while released_fd not in replacements:
            replacements.append(os.open(replacement, os.O_RDONLY))
        activated.close()
        assert os.fstat(released_fd).st_size == len("still open")
        assert activated.all_files_verified is False
        with pytest.raises(ModelVerificationError, match="closed"):
            activated.files[0].load_with(runtime_adapter)  # type: ignore[arg-type]
        with pytest.raises(ModelVerificationError, match="closed"):
            activated.load_with(runtime_adapter, runtime_receipt_verifier)  # type: ignore[arg-type]
        assert runtime_adapter.open_duplicate_fd_count == 0  # type: ignore[attr-defined]
    finally:
        for descriptor in replacements:
            os.close(descriptor)


def test_adapter_failure_closes_every_duplicated_runtime_handle(
    installed_model: object,
    failing_runtime_adapter: object,
    runtime_receipt_verifier: object,
) -> None:
    activated = installed_model.registry.activate(installed_model.model_id)  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError):
        activated.load_with(failing_runtime_adapter, runtime_receipt_verifier)
    assert failing_runtime_adapter.open_duplicate_fd_count == 0  # type: ignore[attr-defined]
    assert failing_runtime_adapter.abort_calls == 1  # type: ignore[attr-defined]


@pytest.mark.parametrize("failure", ("finish_model", "receipt_verifier"))
def test_unverified_runtime_is_aborted_and_never_published(
    installed_model: object,
    runtime_adapter: object,
    runtime_receipt_verifier: object,
    failure: str,
) -> None:
    runtime_adapter.fail_at(failure, runtime_receipt_verifier)  # type: ignore[attr-defined]
    activated = installed_model.registry.activate(installed_model.model_id)  # type: ignore[attr-defined]
    with pytest.raises((RuntimeError, ModelVerificationError)):
        activated.load_with(runtime_adapter, runtime_receipt_verifier)
    assert runtime_adapter.abort_calls == 1  # type: ignore[attr-defined]
    assert runtime_adapter.pending_runtime_count == 0  # type: ignore[attr-defined]
    assert runtime_adapter.published_runtime_count == 0  # type: ignore[attr-defined]
    assert runtime_adapter.open_duplicate_fd_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "race",
    (
        "swap_root_before_open",
        "swap_revision_during_open",
        "swap_file_during_open",
        "grow_file_during_hash",
        "truncate_file_during_hash",
        "overwrite_same_size_during_load",
    ),
)
def test_activation_races_fail_or_load_only_bytes_matching_manifest(
    governed_model_case: object,
    runtime_adapter: object,
    race: str,
) -> None:
    result = governed_model_case.race_activation(race, runtime_adapter)  # type: ignore[attr-defined]
    assert result.failed_closed or (  # type: ignore[attr-defined]
        result.loaded_sha256 == governed_model_case.expected_sha256  # type: ignore[attr-defined]
    )


@pytest.mark.parametrize(
    "network_fault",
    (
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
    ),
)
def test_install_rejects_redirect_lan_oversize_and_partial_downloads(
    governed_model_case: object,
    network_fault: str,
) -> None:
    governed_model_case.network.inject(network_fault)  # type: ignore[attr-defined]
    with pytest.raises((PermissionError, ValueError, TimeoutError)):
        governed_model_case.install()  # type: ignore[attr-defined]
    assert not governed_model_case.final_revision_exists()  # type: ignore[attr-defined]
    assert governed_model_case.previous_revision_unchanged()  # type: ignore[attr-defined]
    assert governed_model_case.network.followed_redirects == []  # type: ignore[attr-defined]


class _ResolverPipeEnd:
    def __init__(self, *, poll_result: bool = True, payload: object = None) -> None:
        self.poll_result = poll_result
        self.payload = payload
        self.closed = False
        self.poll_timeouts: list[float] = []

    def poll(self, timeout: float) -> bool:
        self.poll_timeouts.append(timeout)
        return self.poll_result

    def recv(self) -> object:
        return self.payload

    def close(self) -> None:
        self.closed = True


class _ResolverProcess:
    def __init__(self, *, alive: bool, start_error: BaseException | None = None) -> None:
        self.alive = alive
        self.start_error = start_error
        self.pid: int | None = None
        self.started = False
        self.terminate_calls = 0
        self.kill_calls = 0
        self.join_calls = 0
        self.is_alive_calls = 0
        self.close_calls = 0

    def start(self) -> None:
        self.started = True
        if self.start_error is not None:
            raise self.start_error
        self.pid = 1234

    def is_alive(self) -> bool:
        self.is_alive_calls += 1
        return self.alive

    def terminate(self) -> None:
        self.terminate_calls += 1
        self.alive = False

    def kill(self) -> None:
        self.kill_calls += 1
        self.alive = False

    def join(self, _timeout: float | None = None) -> None:
        self.join_calls += 1

    def close(self) -> None:
        self.close_calls += 1


class _ResolverContext:
    def __init__(
        self,
        *,
        poll_result: bool,
        payload: object,
        process_alive: bool,
        start_error: BaseException | None = None,
    ) -> None:
        self.receive = _ResolverPipeEnd(poll_result=poll_result, payload=payload)
        self.send = _ResolverPipeEnd()
        self.process = _ResolverProcess(alive=process_alive, start_error=start_error)

    def Pipe(self, *, duplex: bool) -> tuple[_ResolverPipeEnd, _ResolverPipeEnd]:
        assert duplex is False
        return self.receive, self.send

    def Process(self, **_kwargs: object) -> _ResolverProcess:
        return self.process


@pytest.mark.parametrize(
    ("poll_result", "payload", "process_alive", "expected"),
    (
        (True, ("ok", ["8.8.8.8"]), False, None),
        (True, ("ok", ["127.0.0.1"]), False, PermissionError),
        (True, ("ok", ["224.0.0.1"]), False, PermissionError),
        (True, ("ok", ["ff0e::1"]), False, PermissionError),
        (False, None, True, TimeoutError),
    ),
)
def test_production_resolver_validates_addresses_and_cleans_child(
    monkeypatch: pytest.MonkeyPatch,
    poll_result: bool,
    payload: object,
    process_alive: bool,
    expected: type[BaseException] | None,
) -> None:
    context = _ResolverContext(
        poll_result=poll_result,
        payload=payload,
        process_alive=process_alive,
    )
    monkeypatch.setattr(network_module.multiprocessing, "get_context", lambda _kind: context)
    if expected is None:
        assert network_module.resolve_public_addresses_bounded(
            "models.example.test", time.monotonic() + 1
        ) == ("8.8.8.8",)
    else:
        with pytest.raises(expected):
            network_module.resolve_public_addresses_bounded(
                "models.example.test", time.monotonic() + 1
            )
    assert context.process.started is True
    assert context.process.join_calls >= 1
    assert context.receive.closed is True
    assert context.send.closed is True
    assert context.process.close_calls == 1
    if not poll_result:
        assert context.process.terminate_calls == 1


def test_production_resolver_start_failure_closes_all_owned_handles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _ResolverContext(
        poll_result=False,
        payload=None,
        process_alive=False,
        start_error=RuntimeError("scripted start failure"),
    )
    monkeypatch.setattr(network_module.multiprocessing, "get_context", lambda _kind: context)
    with pytest.raises(RuntimeError, match="scripted start failure"):
        network_module.resolve_public_addresses_bounded("models.example.test", time.monotonic() + 1)
    assert context.receive.closed is True
    assert context.send.closed is True
    assert context.process.is_alive_calls == 0
    assert context.process.close_calls == 1


def test_production_resolver_recomputes_deadline_after_process_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _ResolverContext(
        poll_result=False,
        payload=None,
        process_alive=False,
    )
    clock = [100.0]
    original_start = context.process.start

    def slow_start() -> None:
        original_start()
        clock[0] = 102.0

    monkeypatch.setattr(context.process, "start", slow_start)
    monkeypatch.setattr(network_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(network_module.multiprocessing, "get_context", lambda _kind: context)

    with pytest.raises(TimeoutError, match="model download total deadline"):
        network_module.resolve_public_addresses_bounded("models.example.test", 101.0)

    assert context.receive.poll_timeouts == []
    assert context.receive.closed is True
    assert context.send.closed is True
    assert context.process.close_calls == 1


class _HandshakeSocket:
    def __init__(self) -> None:
        self.closed = threading.Event()

    def close(self) -> None:
        self.closed.set()


class _StalledTlsContext:
    def __init__(self) -> None:
        self.server_hostname: str | None = None
        self.released_by_deadline_close = False

    def wrap_socket(self, raw: _HandshakeSocket, *, server_hostname: str) -> object:
        self.server_hostname = server_hostname
        self.released_by_deadline_close = raw.closed.wait(0.5)
        raise TimeoutError("stalled TLS handshake")


def test_pinned_https_total_deadline_closes_stalled_tls_handshake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _HandshakeSocket()
    tls = _StalledTlsContext()
    connected_to: list[tuple[str, int]] = []

    def fake_create_connection(address: tuple[str, int], _timeout: float) -> _HandshakeSocket:
        connected_to.append(address)
        return raw

    monkeypatch.setattr(network_module.ssl, "create_default_context", lambda: tls)
    monkeypatch.setattr(network_module.socket, "create_connection", fake_create_connection)
    monkeypatch.setattr(
        network_module,
        "resolve_public_addresses_bounded",
        lambda _hostname, _deadline: ("8.8.8.8",),
    )
    started = time.monotonic()
    with (
        pytest.raises(TimeoutError),
        network_module.PinnedHttpsTransport().stream_exact(
            "https://models.example.test/mini.onnx",
            frozenset({"models.example.test"}),
            started + 0.05,
        ),
    ):
        raise AssertionError("stalled handshake yielded a response")
    assert raw.closed.is_set()
    assert tls.released_by_deadline_close is True
    assert connected_to == [("8.8.8.8", 443)]
    assert tls.server_hostname == "models.example.test"


def test_two_installers_publish_one_complete_immutable_revision(
    concurrent_model_case: object,
) -> None:
    results = concurrent_model_case.run_two_installers()  # type: ignore[attr-defined]
    assert concurrent_model_case.maximum_simultaneous_lock_holders == 1  # type: ignore[attr-defined]
    assert concurrent_model_case.published_revision_count == 1  # type: ignore[attr-defined]
    assert all(result.all_files_verified for result in results)
    assert concurrent_model_case.no_stage_directory_remains()  # type: ignore[attr-defined]


@pytest.mark.parametrize("body_fails", (False, True), ids=("success", "body-failure"))
@pytest.mark.parametrize("cleanup_fault", ("unlock", "close"))
def test_owned_directory_lock_cleanup_preserves_primary_and_releases_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    body_fails: bool,
    cleanup_fault: str,
) -> None:
    root_path = tmp_path / "model-root"
    root_path.mkdir(mode=0o700)
    root = OwnedDirectory.open(root_path)
    lock_name = ".cleanup-fault.lock"
    primary = RuntimeError("scripted protected-body failure")
    secondary = OSError(f"scripted lock {cleanup_fault} failure")
    lock_descriptor: int | None = None
    unlock_attempts = 0
    close_attempts = 0
    fault_active = True
    real_open_regular = fs_module.open_regular_at
    real_flock = fcntl.flock
    real_close = os.close

    def capture_lock_descriptor(
        directory: OwnedDirectory,
        name: str,
        flags: int,
        *,
        mode: int = 0o600,
        expected_mode: int | None = None,
    ) -> int:
        nonlocal lock_descriptor
        descriptor = real_open_regular(
            directory,
            name,
            flags,
            mode=mode,
            expected_mode=expected_mode,
        )
        if fault_active and name == lock_name:
            lock_descriptor = descriptor
        return descriptor

    def fail_unlock(descriptor: int, operation: int) -> None:
        nonlocal unlock_attempts
        real_flock(descriptor, operation)
        if fault_active and descriptor == lock_descriptor and operation == fcntl.LOCK_UN:
            unlock_attempts += 1
            if cleanup_fault == "unlock":
                raise secondary

    def fail_lock_close(descriptor: int) -> None:
        nonlocal close_attempts
        is_target = fault_active and descriptor == lock_descriptor
        real_close(descriptor)
        if is_target:
            close_attempts += 1
            if cleanup_fault == "close":
                raise secondary

    monkeypatch.setattr(fs_module, "open_regular_at", capture_lock_descriptor)
    monkeypatch.setattr(fcntl, "flock", fail_unlock)
    monkeypatch.setattr(os, "close", fail_lock_close)

    caught: BaseException | None = None
    try:
        with root.lock(lock_name, timeout_seconds=1.0):
            if body_fails:
                raise primary
    except BaseException as error:
        caught = error
    finally:
        fault_active = False

    if body_fails:
        assert caught is primary
        assert getattr(primary, "__notes__", []) == ["additional descriptor cleanup failure"]
    else:
        assert caught is secondary
        assert getattr(secondary, "__notes__", []) == []
    assert unlock_attempts == 1
    assert close_attempts == 1
    assert lock_descriptor is not None
    with pytest.raises(OSError):
        os.fstat(lock_descriptor)

    with root.lock(lock_name, timeout_seconds=1.0):
        pass
    root.close()


def test_unrelated_installed_model_activates_while_download_is_paused(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer_model_id = governed_model_case.install_peer_model()  # type: ignore[attr-defined]
    download_paused = threading.Event()
    release_download = threading.Event()
    shared_lock_attempted = threading.Event()
    activation_done = threading.Event()
    install_results: list[object] = []
    activation_results: list[object] = []
    failures: list[BaseException] = []
    lock_names: list[str] = []
    real_lock = OwnedDirectory.lock

    @contextlib.contextmanager
    def track_lock(
        directory: OwnedDirectory,
        name: str,
        *,
        timeout_seconds: float,
        shared: bool = False,
    ):
        lock_names.append(name)
        if shared:
            shared_lock_attempted.set()
        with real_lock(
            directory,
            name,
            timeout_seconds=timeout_seconds,
            shared=shared,
        ):
            yield

    monkeypatch.setattr(OwnedDirectory, "lock", track_lock)

    def pause_download(point: str) -> None:
        if point != "after_each_file":
            return
        download_paused.set()
        if not release_download.wait(timeout=10):
            raise TimeoutError("scripted download pause timed out")

    def install_target() -> None:
        try:
            install_results.append(
                governed_model_case._installer(  # type: ignore[attr-defined]
                    fault_hook=pause_download
                ).install(governed_model_case.model_id)  # type: ignore[attr-defined]
            )
        except BaseException as error:
            failures.append(error)

    def activate_peer() -> None:
        try:
            activation_results.append(
                governed_model_case.registry.activate(peer_model_id)  # type: ignore[attr-defined]
            )
        except BaseException as error:
            failures.append(error)
        finally:
            activation_done.set()

    installer_thread = threading.Thread(target=install_target)
    activation_thread = threading.Thread(target=activate_peer)
    installer_thread.start()
    assert download_paused.wait(timeout=10)
    activation_thread.start()
    assert shared_lock_attempted.wait(timeout=10)
    completed_while_paused = activation_done.wait(timeout=2)
    release_download.set()
    installer_thread.join(timeout=10)
    activation_thread.join(timeout=10)

    try:
        assert not installer_thread.is_alive()
        assert not activation_thread.is_alive()
        if failures:
            raise failures[0]
        assert completed_while_paused
        assert len(install_results) == 1
        assert len(activation_results) == 1
        assert set(lock_names) == {
            fs_module.model_install_lock_name(governed_model_case.model_id),  # type: ignore[attr-defined]
            fs_module.model_install_lock_name(peer_model_id),
        }
    finally:
        for result in (*install_results, *activation_results):
            result.close()  # type: ignore[attr-defined]


def test_same_model_activation_waits_for_paused_install_commit(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    download_paused = threading.Event()
    release_download = threading.Event()
    shared_lock_attempted = threading.Event()
    activation_done = threading.Event()
    install_results: list[object] = []
    activation_results: list[object] = []
    failures: list[BaseException] = []
    lock_names: list[str] = []
    real_lock = OwnedDirectory.lock

    @contextlib.contextmanager
    def track_lock(
        directory: OwnedDirectory,
        name: str,
        *,
        timeout_seconds: float,
        shared: bool = False,
    ):
        lock_names.append(name)
        if shared:
            shared_lock_attempted.set()
        with real_lock(
            directory,
            name,
            timeout_seconds=timeout_seconds,
            shared=shared,
        ):
            yield

    monkeypatch.setattr(OwnedDirectory, "lock", track_lock)

    def pause_download(point: str) -> None:
        if point != "after_each_file":
            return
        download_paused.set()
        if not release_download.wait(timeout=10):
            raise TimeoutError("scripted download pause timed out")

    def install_target() -> None:
        try:
            install_results.append(
                governed_model_case._installer(  # type: ignore[attr-defined]
                    fault_hook=pause_download
                ).install(governed_model_case.model_id)  # type: ignore[attr-defined]
            )
        except BaseException as error:
            failures.append(error)

    def activate_target() -> None:
        try:
            activation_results.append(
                governed_model_case.registry.activate(  # type: ignore[attr-defined]
                    governed_model_case.model_id  # type: ignore[attr-defined]
                )
            )
        except BaseException as error:
            failures.append(error)
        finally:
            activation_done.set()

    installer_thread = threading.Thread(target=install_target)
    activation_thread = threading.Thread(target=activate_target)
    installer_thread.start()
    assert download_paused.wait(timeout=10)
    activation_thread.start()
    assert shared_lock_attempted.wait(timeout=10)
    remained_excluded = not activation_done.wait(timeout=0.3)
    release_download.set()
    installer_thread.join(timeout=10)
    activation_thread.join(timeout=10)

    try:
        assert not installer_thread.is_alive()
        assert not activation_thread.is_alive()
        if failures:
            raise failures[0]
        assert remained_excluded
        assert len(install_results) == 1
        assert len(activation_results) == 1
        assert lock_names == [
            fs_module.model_install_lock_name(governed_model_case.model_id),  # type: ignore[attr-defined]
            fs_module.model_install_lock_name(governed_model_case.model_id),  # type: ignore[attr-defined]
        ]
    finally:
        for result in (*install_results, *activation_results):
            result.close()  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "mutation",
    ("missing", "symlink", "fifo", "writable", "wrong_size", "hardlink"),
)
def test_activation_requires_exact_positive_publication_commit(
    governed_model_case: object,
    mutation: str,
) -> None:
    installed = governed_model_case.install()  # type: ignore[attr-defined]
    installed.close()
    commit_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]

    if mutation == "missing":
        commit_path.unlink()
    elif mutation == "symlink":
        displaced = commit_path.with_name(".displaced-publication-proof")
        commit_path.rename(displaced)
        commit_path.symlink_to(displaced.name)
    elif mutation == "fifo":
        commit_path.unlink()
        os.mkfifo(commit_path, mode=0o400)
        commit_path.chmod(0o400)
    elif mutation == "writable":
        commit_path.chmod(0o600)
    elif mutation == "wrong_size":
        commit_path.chmod(0o600)
        commit_path.write_bytes(b"not-empty")
        commit_path.chmod(0o400)
    elif mutation == "hardlink":
        os.link(commit_path, commit_path.with_name(".linked-publication-proof"))
    else:  # pragma: no cover - closed parametrization
        raise AssertionError(f"unknown publication proof mutation: {mutation}")

    with pytest.raises(RuntimeError, match="model is not installed and verified"):
        governed_model_case.registry.activate(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


def test_activation_revalidates_publication_commit_identity_after_artifact_hash(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed = governed_model_case.install()  # type: ignore[attr-defined]
    installed.close()
    commit_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    displaced = commit_path.with_name(".displaced-publication-proof")
    real_hash = registry_module.hash_exact_fd
    swapped = False

    def swap_commit_after_hash(
        descriptor: int,
        size: int,
        expected_sha256: str,
    ) -> str:
        nonlocal swapped
        result = real_hash(descriptor, size, expected_sha256)
        if not swapped:
            commit_path.rename(displaced)
            commit_path.write_bytes(b"")
            commit_path.chmod(0o400)
            swapped = True
        return result

    monkeypatch.setattr(registry_module, "hash_exact_fd", swap_commit_after_hash)

    with pytest.raises(RuntimeError, match="model is not installed and verified"):
        governed_model_case.registry.activate(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
    assert swapped
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


def test_publication_commit_inode_is_durable_before_read_only_authority(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    model_path = commit_path.parent
    model_metadata = model_path.stat(follow_symlinks=False)
    model_identity = (model_metadata.st_dev, model_metadata.st_ino)
    commit_fsync_modes: list[int] = []
    parent_fsync_modes: list[int] = []
    real_fsync = os.fsync
    real_directory_fsync = OwnedDirectory.fsync

    def track_fsync(descriptor: int) -> None:
        identity = os.fstat(descriptor)
        if commit_path.exists():
            commit = commit_path.stat(follow_symlinks=False)
            if (identity.st_dev, identity.st_ino) == (commit.st_dev, commit.st_ino):
                commit_fsync_modes.append(stat.S_IMODE(identity.st_mode))
        real_fsync(descriptor)

    def track_parent_fsync(directory: OwnedDirectory) -> None:
        identity = (directory.identity.device, directory.identity.inode)
        if identity == model_identity and commit_path.exists():
            parent_fsync_modes.append(stat.S_IMODE(commit_path.stat(follow_symlinks=False).st_mode))
        real_directory_fsync(directory)

    monkeypatch.setattr(os, "fsync", track_fsync)
    monkeypatch.setattr(OwnedDirectory, "fsync", track_parent_fsync)

    activated = governed_model_case.install()  # type: ignore[attr-defined]
    activated.close()

    assert commit_fsync_modes == [0o600, 0o400]
    assert parent_fsync_modes == [0o600]


def test_publication_supports_filesystems_that_cannot_rename_read_only_directories(
    governed_model_case: object,
) -> None:
    governed_model_case.require_write_enabled_publish_source()  # type: ignore[attr-defined]
    activated = governed_model_case.install()  # type: ignore[attr-defined]
    assert activated.all_files_verified
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]


def test_crash_after_publish_before_seal_is_unusable_then_recovered(
    governed_model_case: object,
) -> None:
    governed_model_case.crash_install_at(  # type: ignore[attr-defined]
        "after_publish_before_seal"
    )
    assert governed_model_case.final_revision_exists()  # type: ignore[attr-defined]
    assert governed_model_case.final_revision_mode == 0o700  # type: ignore[attr-defined]
    assert not governed_model_case.final_revision_is_complete_and_verified()  # type: ignore[attr-defined]
    governed_model_case.restart_and_reconcile()  # type: ignore[attr-defined]
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    assert governed_model_case.final_revision_is_complete_and_verified()  # type: ignore[attr-defined]


def test_recovery_raw_cleanup_failure_preserves_wrapper_error(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    governed_model_case.crash_install_at(  # type: ignore[attr-defined]
        "after_publish_before_seal"
    )
    primary = RuntimeError("scripted recovery wrapper construction failure")
    retained_descriptor: list[int] = []
    close_attempts: list[int] = []
    real_close = os.close

    def fail_from_manifest(
        _cls: type[VerifiedModelFile], _item: object, descriptor: int
    ) -> VerifiedModelFile:
        retained_descriptor.append(descriptor)
        raise primary

    def fail_retained_close(descriptor: int) -> None:
        if retained_descriptor and descriptor == retained_descriptor[0]:
            close_attempts.append(descriptor)
            real_close(descriptor)
            raise OSError("scripted recovery descriptor close failure")
        real_close(descriptor)

    monkeypatch.setattr(
        VerifiedModelFile,
        "from_manifest",
        classmethod(fail_from_manifest),
    )
    monkeypatch.setattr(os, "close", fail_retained_close)

    with pytest.raises(RuntimeError) as caught:
        governed_model_case.restart_and_reconcile()  # type: ignore[attr-defined]

    assert caught.value is primary
    assert caught.value.__notes__ == ["additional descriptor cleanup failure"]
    assert close_attempts == retained_descriptor
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


def test_recovery_wrapper_cleanup_failure_preserves_transfer_error(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    governed_model_case.crash_install_at(  # type: ignore[attr-defined]
        "after_publish_before_seal"
    )
    primary = RuntimeError("scripted recovery wrapper transfer failure")
    retained_handle: list[VerifiedModelFile] = []
    close_attempts: list[int] = []
    real_from_manifest = VerifiedModelFile.from_manifest
    real_close = VerifiedModelFile.close

    def capture_from_manifest(
        _cls: type[VerifiedModelFile], item: object, descriptor: int
    ) -> VerifiedModelFile:
        handle = real_from_manifest(item, descriptor)  # type: ignore[arg-type]
        retained_handle.append(handle)
        return handle

    def fail_transfer(point: str) -> None:
        if point == "before_retain_recovery_file":
            raise primary

    def fail_handle_close(handle: VerifiedModelFile) -> None:
        if retained_handle and handle is retained_handle[0]:
            close_attempts.append(id(handle))
            real_close(handle)
            raise OSError("scripted recovery wrapper close failure")
        real_close(handle)

    monkeypatch.setattr(
        VerifiedModelFile,
        "from_manifest",
        classmethod(capture_from_manifest),
    )
    monkeypatch.setattr(VerifiedModelFile, "close", fail_handle_close)

    caught: RuntimeError | None = None
    try:
        activated = governed_model_case._installer(  # type: ignore[attr-defined]
            fault_hook=fail_transfer
        ).install(governed_model_case.model_id)  # type: ignore[attr-defined]
    except RuntimeError as error:
        caught = error
    else:
        activated.close()

    assert caught is primary
    assert caught.__notes__ == ["additional descriptor cleanup failure"]
    assert close_attempts == [id(retained_handle[0])]
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


def test_recovery_revision_close_failure_closes_every_artifact_once(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    governed_model_case.crash_install_at(  # type: ignore[attr-defined]
        "after_publish_before_seal"
    )
    revision_path = (
        governed_model_case.model_root
        / governed_model_case.model_id
        / (  # type: ignore[attr-defined]
            "a" * 40
        )
    )
    revision_metadata = revision_path.stat(follow_symlinks=False)
    revision_identity = (revision_metadata.st_dev, revision_metadata.st_ino)
    directory_close_failed = False
    artifact_close_attempts: list[int] = []
    real_directory_close = OwnedDirectory.close
    real_artifact_close = VerifiedModelFile.close

    def fail_revision_close(directory: OwnedDirectory) -> None:
        nonlocal directory_close_failed
        directory_identity = (directory.identity.device, directory.identity.inode)
        if directory_identity == revision_identity and not directory_close_failed:
            directory_close_failed = True
            real_directory_close(directory)
            raise OSError("scripted recovery revision close failure")
        real_directory_close(directory)

    def track_artifact_close(handle: VerifiedModelFile) -> None:
        artifact_close_attempts.append(id(handle))
        real_artifact_close(handle)

    monkeypatch.setattr(OwnedDirectory, "close", fail_revision_close)
    monkeypatch.setattr(VerifiedModelFile, "close", track_artifact_close)

    with pytest.raises(OSError, match="scripted recovery revision close failure"):
        governed_model_case.restart_and_reconcile()  # type: ignore[attr-defined]

    assert directory_close_failed is True
    assert len(artifact_close_attempts) == 1
    assert len(set(artifact_close_attempts)) == 1
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "mutation",
    (
        "unexpected_file",
        "missing_artifact",
        "artifact_symlink",
        "artifact_fifo",
        "writable_artifact",
        "wrong_size",
        "hash_mismatch",
    ),
)
def test_unsealed_revision_tampering_is_never_sealed_or_loaded(
    governed_model_case: object,
    mutation: str,
) -> None:
    governed_model_case.crash_install_at(  # type: ignore[attr-defined]
        "after_publish_before_seal"
    )
    governed_model_case.mutate_unsealed_revision(mutation)  # type: ignore[attr-defined]
    with pytest.raises((PermissionError, ValueError)):
        governed_model_case.restart_and_reconcile()  # type: ignore[attr-defined]
    assert governed_model_case.final_revision_mode == 0o700  # type: ignore[attr-defined]
    assert not governed_model_case.final_revision_is_complete_and_verified()  # type: ignore[attr-defined]
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("fault", ("mutate_artifact", "raise_error"))
def test_recovery_fault_between_seal_and_verification_restores_unsealed_state(
    governed_model_case: object,
    fault: str,
) -> None:
    governed_model_case.crash_install_at(  # type: ignore[attr-defined]
        "after_publish_before_seal"
    )

    with pytest.raises((PermissionError, RuntimeError, ValueError)):
        governed_model_case.restart_with_post_seal_recovery_fault(  # type: ignore[attr-defined]
            fault
        )

    assert governed_model_case.final_revision_mode == 0o700  # type: ignore[attr-defined]
    assert not governed_model_case.final_revision_is_complete_and_verified()  # type: ignore[attr-defined]
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("rollback_fault", ("chmod", "fsync", "close"))
def test_post_seal_failure_remains_quarantined_when_rollback_fails(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    rollback_fault: str,
) -> None:
    governed_model_case.crash_install_at(  # type: ignore[attr-defined]
        "after_publish_before_seal"
    )
    revision = (
        governed_model_case.model_root  # type: ignore[attr-defined]
        / governed_model_case.model_id  # type: ignore[attr-defined]
        / ("a" * 40)
    )
    metadata = revision.stat(follow_symlinks=False)
    revision_identity = (metadata.st_dev, metadata.st_ino)
    primary = RuntimeError("scripted post-seal recovery failure")
    rollback_attempts: list[str] = []
    real_chmod = OwnedDirectory.chmod
    real_fsync = OwnedDirectory.fsync
    real_close = OwnedDirectory.close

    def is_revision(directory: OwnedDirectory) -> bool:
        return (directory.identity.device, directory.identity.inode) == revision_identity

    def fail_rollback_chmod(directory: OwnedDirectory, mode: int) -> None:
        if (
            rollback_fault == "chmod"
            and is_revision(directory)
            and mode == 0o700
            and not rollback_attempts
        ):
            rollback_attempts.append("chmod")
            raise OSError("scripted rollback chmod failure")
        real_chmod(directory, mode)

    def fail_rollback_fsync(directory: OwnedDirectory) -> None:
        if (
            rollback_fault == "fsync"
            and is_revision(directory)
            and stat.S_IMODE(os.fstat(directory.fd).st_mode) == 0o700
            and not rollback_attempts
        ):
            rollback_attempts.append("fsync")
            raise OSError("scripted rollback fsync failure")
        real_fsync(directory)

    def fail_rollback_close(directory: OwnedDirectory) -> None:
        if rollback_fault == "close" and is_revision(directory) and not rollback_attempts:
            rollback_attempts.append("close")
            real_close(directory)
            raise OSError("scripted rollback close failure")
        real_close(directory)

    def fail_after_seal(point: str) -> None:
        if point == "after_recovery_seal_before_verify":
            raise primary

    monkeypatch.setattr(OwnedDirectory, "chmod", fail_rollback_chmod)
    monkeypatch.setattr(OwnedDirectory, "fsync", fail_rollback_fsync)
    monkeypatch.setattr(OwnedDirectory, "close", fail_rollback_close)

    caught: BaseException | None = None
    try:
        governed_model_case._installer(  # type: ignore[attr-defined]
            fault_hook=fail_after_seal
        ).install(governed_model_case.model_id)  # type: ignore[attr-defined]
    except BaseException as error:
        caught = error

    assert caught is primary
    assert rollback_attempts == [rollback_fault]
    expected_note = (
        "additional descriptor cleanup failure"
        if rollback_fault == "close"
        else "additional recovery rollback failure"
    )
    assert caught.__notes__ == [expected_note]
    assert governed_model_case.recovery_marker_exists  # type: ignore[attr-defined]
    assert governed_model_case.final_revision_mode == (  # type: ignore[attr-defined]
        0o500 if rollback_fault == "chmod" else 0o700
    )
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]

    activation_probe = (
        "from pathlib import Path\n"
        "import sys\n"
        "from tuntun_core.services.models.registry import ModelRegistry\n"
        "registry = ModelRegistry.load(Path(sys.argv[1]), model_root=Path(sys.argv[2]))\n"
        "try:\n"
        "    activated = registry.activate(sys.argv[3])\n"
        "except RuntimeError:\n"
        "    raise SystemExit(0)\n"
        "activated.close()\n"
        "raise SystemExit(1)\n"
    )
    restarted = subprocess.run(
        [
            sys.executable,
            "-c",
            activation_probe,
            str(governed_model_case.manifest),  # type: ignore[attr-defined]
            str(governed_model_case.model_root),  # type: ignore[attr-defined]
            governed_model_case.model_id,  # type: ignore[attr-defined]
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert restarted.returncode == 0, restarted.stderr

    governed_model_case.restart_and_reconcile()  # type: ignore[attr-defined]
    assert not governed_model_case.recovery_marker_exists  # type: ignore[attr-defined]
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    assert governed_model_case.final_revision_is_complete_and_verified()  # type: ignore[attr-defined]


def test_fresh_post_seal_failure_is_durably_quarantined_until_recovery(
    governed_model_case: object,
) -> None:
    governed_model_case.crash_install_at(  # type: ignore[attr-defined]
        "after_publish_before_parent_fsync"
    )

    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    assert governed_model_case.recovery_marker_exists  # type: ignore[attr-defined]
    fresh_registry = ModelRegistry.load(
        governed_model_case.manifest,  # type: ignore[attr-defined]
        model_root=governed_model_case.model_root,  # type: ignore[attr-defined]
    )
    with pytest.raises(RuntimeError, match="model is not installed and verified"):
        fresh_registry.activate(governed_model_case.model_id)  # type: ignore[attr-defined]

    governed_model_case.restart_and_reconcile()  # type: ignore[attr-defined]
    assert not governed_model_case.recovery_marker_exists  # type: ignore[attr-defined]
    assert governed_model_case.final_revision_is_complete_and_verified()  # type: ignore[attr-defined]


def test_successful_recovery_persists_marker_before_seal_and_removal_after_verify(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    governed_model_case.crash_install_at(  # type: ignore[attr-defined]
        "after_publish_before_seal"
    )
    model_path = (
        governed_model_case.model_root  # type: ignore[attr-defined]
        / governed_model_case.model_id  # type: ignore[attr-defined]
    )
    revision_path = model_path / ("a" * 40)
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    commit_path = model_path / f".publication-verified-{'a' * 40}"
    model_metadata = model_path.stat(follow_symlinks=False)
    revision_metadata = revision_path.stat(follow_symlinks=False)
    model_identity = (model_metadata.st_dev, model_metadata.st_ino)
    revision_identity = (revision_metadata.st_dev, revision_metadata.st_ino)
    events: list[str] = []
    real_fsync = os.fsync
    real_unlink = os.unlink
    real_chmod = OwnedDirectory.chmod
    real_hash = installer_module.hash_exact_fd

    def track_fsync(descriptor: int) -> None:
        identity = os.fstat(descriptor)
        descriptor_identity = (identity.st_dev, identity.st_ino)
        if commit_path.exists():
            commit = commit_path.stat(follow_symlinks=False)
            if descriptor_identity == (commit.st_dev, commit.st_ino):
                events.append(f"commit_fsync_{stat.S_IMODE(identity.st_mode):03o}")
            elif descriptor_identity == model_identity:
                events.append("model_fsync")
            elif descriptor_identity == revision_identity:
                events.append("revision_fsync")
        elif marker_path.exists():
            marker = marker_path.stat(follow_symlinks=False)
            if descriptor_identity == (marker.st_dev, marker.st_ino):
                events.append("marker_fsync")
            elif descriptor_identity == model_identity:
                events.append("model_fsync")
            elif descriptor_identity == revision_identity:
                events.append("revision_fsync")
        elif descriptor_identity == model_identity:
            events.append("model_fsync")
        elif descriptor_identity == revision_identity:
            events.append("revision_fsync")
        real_fsync(descriptor)

    def track_unlink(path: str, *, dir_fd: int | None = None) -> None:
        if path == marker_path.name:
            events.append("marker_unlink")
        real_unlink(path, dir_fd=dir_fd)

    def track_chmod(directory: OwnedDirectory, mode: int) -> None:
        if (
            directory.identity.device,
            directory.identity.inode,
        ) == revision_identity and mode == 0o500:
            events.append("seal")
        real_chmod(directory, mode)

    def track_hash(descriptor: int, size: int, sha256: str) -> str:
        mode = stat.S_IMODE(revision_path.stat(follow_symlinks=False).st_mode)
        events.append("post_seal_hash" if mode == 0o500 else "pre_seal_hash")
        return real_hash(descriptor, size, sha256)

    monkeypatch.setattr(os, "fsync", track_fsync)
    monkeypatch.setattr(os, "unlink", track_unlink)
    monkeypatch.setattr(OwnedDirectory, "chmod", track_chmod)
    monkeypatch.setattr(installer_module, "hash_exact_fd", track_hash)

    governed_model_case.restart_and_reconcile()  # type: ignore[attr-defined]

    marker_fsync = events.index("marker_fsync")
    assert events[marker_fsync:] == [
        "marker_fsync",
        "model_fsync",
        "seal",
        "revision_fsync",
        "post_seal_hash",
        "revision_fsync",
        "model_fsync",
        "marker_unlink",
        "model_fsync",
        "commit_fsync_600",
        "model_fsync",
        "commit_fsync_400",
    ]
    assert not governed_model_case.recovery_marker_exists  # type: ignore[attr-defined]


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
def test_marker_clear_parent_fsync_failure_blocks_cross_process_until_retry(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    if phase == "recovery":
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
    model_path = (
        governed_model_case.model_root  # type: ignore[attr-defined]
        / governed_model_case.model_id  # type: ignore[attr-defined]
    )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    model_metadata = model_path.stat(follow_symlinks=False)
    model_identity = (model_metadata.st_dev, model_metadata.st_ino)
    primary = OSError("scripted marker-clear parent fsync failure")
    secondary = OSError("scripted marker close failure")
    marker_unlinked = False
    clear_fsync_attempts = 0
    marker_descriptors: set[int] = set()
    marker_close_attempts: list[int] = []
    marker_close_fault_injected = False
    child_returncode_during_window: int | None = None
    real_unlink = os.unlink
    real_fsync = OwnedDirectory.fsync
    real_close = os.close
    real_clear = ModelInstaller._clear_recovery_marker
    signal_root = governed_model_case.model_root.parent  # type: ignore[attr-defined]
    child_ready = signal_root / f"activation-ready-{phase}"
    child_start = signal_root / f"activation-start-{phase}"
    activation_probe = (
        "from pathlib import Path\n"
        "import sys,time\n"
        "from tuntun_core.services.models.registry import ModelRegistry\n"
        "manifest,root,model_id,ready,start=Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3],Path(sys.argv[4]),Path(sys.argv[5])\n"
        "registry=ModelRegistry.load(manifest,model_root=root)\n"
        "ready.write_text('ready',encoding='utf-8')\n"
        "deadline=time.monotonic()+10\n"
        "while not start.exists():\n"
        "    if time.monotonic()>=deadline: raise SystemExit(3)\n"
        "    time.sleep(0.01)\n"
        "try:\n"
        "    activated=registry.activate(model_id)\n"
        "except RuntimeError:\n"
        "    raise SystemExit(0)\n"
        "activated.close()\n"
        "raise SystemExit(1)\n"
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            activation_probe,
            str(governed_model_case.manifest),  # type: ignore[attr-defined]
            str(governed_model_case.model_root),  # type: ignore[attr-defined]
            governed_model_case.model_id,  # type: ignore[attr-defined]
            str(child_ready),
            str(child_start),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    startup_deadline = time.monotonic() + 10
    while not child_ready.exists():
        if process.poll() is not None:
            _stdout, stderr = process.communicate()
            pytest.fail(f"activation child exited before readiness: {stderr}")
        if time.monotonic() >= startup_deadline:
            pytest.fail("activation child startup timed out")
        time.sleep(0.01)

    def track_marker_unlink(path: str, *, dir_fd: int | None = None) -> None:
        nonlocal marker_unlinked
        real_unlink(path, dir_fd=dir_fd)
        if path == marker_path.name:
            marker_unlinked = True

    def fail_clear_parent_fsync(directory: OwnedDirectory) -> None:
        nonlocal clear_fsync_attempts
        nonlocal child_returncode_during_window
        identity = (directory.identity.device, directory.identity.inode)
        if identity == model_identity and marker_unlinked and clear_fsync_attempts == 0:
            clear_fsync_attempts += 1
            child_start.write_text("activate", encoding="utf-8")
            observation_deadline = time.monotonic() + 1
            while process.poll() is None and time.monotonic() < observation_deadline:
                time.sleep(0.01)
            child_returncode_during_window = process.poll()
            raise primary
        real_fsync(directory)

    def capture_marker_descriptor(
        model: OwnedDirectory,
        revision: str,
        descriptor: int,
    ) -> None:
        marker_descriptors.add(descriptor)
        real_clear(model, revision, descriptor)

    def fail_marker_close(descriptor: int) -> None:
        nonlocal marker_close_fault_injected
        if descriptor in marker_descriptors:
            marker_close_attempts.append(descriptor)
        real_close(descriptor)
        if descriptor in marker_descriptors and not marker_close_fault_injected:
            marker_close_fault_injected = True
            raise secondary

    monkeypatch.setattr(os, "unlink", track_marker_unlink)
    monkeypatch.setattr(os, "close", fail_marker_close)
    monkeypatch.setattr(OwnedDirectory, "fsync", fail_clear_parent_fsync)
    monkeypatch.setattr(
        ModelInstaller,
        "_clear_recovery_marker",
        staticmethod(capture_marker_descriptor),
    )

    try:
        caught: BaseException | None = None
        try:
            governed_model_case.install()  # type: ignore[attr-defined]
        except BaseException as error:
            caught = error

        assert caught is primary
        assert getattr(primary, "__notes__", []) == ["additional descriptor cleanup failure"]
        assert clear_fsync_attempts == 1
        assert len(marker_close_attempts) == 1
        assert child_returncode_during_window is None
        _stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stderr
        assert governed_model_case.recovery_marker_exists  # type: ignore[attr-defined]
        expected_mode = 0o500 if phase == "fresh" else 0o700
        assert governed_model_case.final_revision_mode == expected_mode  # type: ignore[attr-defined]
        assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]

        same_process_registry = ModelRegistry.load(
            governed_model_case.manifest,  # type: ignore[attr-defined]
            model_root=governed_model_case.model_root,  # type: ignore[attr-defined]
        )
        same_process_denied = False
        try:
            unexpected = same_process_registry.activate(
                governed_model_case.model_id  # type: ignore[attr-defined]
            )
        except RuntimeError:
            same_process_denied = True
        else:
            unexpected.close()
        assert same_process_denied

        recovered = governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
        recovered.close()
        assert not governed_model_case.recovery_marker_exists  # type: ignore[attr-defined]
        assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
        activated = same_process_registry.activate(
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
        try:
            assert activated.all_files_verified
        finally:
            activated.close()
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate()
        governed_model_case.clear_process_publication_uncertainty()  # type: ignore[attr-defined]


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
def test_marker_disappearance_at_clear_revalidation_is_cross_process_quarantined(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    if phase == "recovery":
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
    model_path = (
        governed_model_case.model_root  # type: ignore[attr-defined]
        / governed_model_case.model_id  # type: ignore[attr-defined]
    )
    revision_path = model_path / ("a" * 40)
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    primary = OSError("scripted marker disappearance at clear revalidation")
    fault_injected = False
    real_require = ModelInstaller._require_recovery_marker

    def remove_marker_at_clear_revalidation(
        model: OwnedDirectory,
        revision: str,
        descriptor: int,
    ) -> None:
        nonlocal fault_injected
        if (
            not fault_injected
            and marker_path.exists()
            and stat.S_IMODE(revision_path.stat(follow_symlinks=False).st_mode) == 0o500
        ):
            marker_path.unlink()
            fault_injected = True
            raise primary
        real_require(model, revision, descriptor)

    monkeypatch.setattr(
        ModelInstaller,
        "_require_recovery_marker",
        staticmethod(remove_marker_at_clear_revalidation),
    )

    caught: BaseException | None = None
    try:
        governed_model_case.install()  # type: ignore[attr-defined]
    except BaseException as error:
        caught = error

    assert caught is primary
    assert fault_injected
    assert governed_model_case.recovery_marker_exists  # type: ignore[attr-defined]
    expected_mode = 0o500 if phase == "fresh" else 0o700
    assert governed_model_case.final_revision_mode == expected_mode  # type: ignore[attr-defined]
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]

    denial_probe = (
        "from pathlib import Path\n"
        "import sys\n"
        "from tuntun_core.services.models.registry import ModelRegistry\n"
        "registry=ModelRegistry.load(Path(sys.argv[1]),model_root=Path(sys.argv[2]))\n"
        "try:\n"
        "    activated=registry.activate(sys.argv[3])\n"
        "except RuntimeError:\n"
        "    raise SystemExit(0)\n"
        "activated.close()\n"
        "raise SystemExit(1)\n"
    )
    denied = subprocess.run(
        [
            sys.executable,
            "-c",
            denial_probe,
            str(governed_model_case.manifest),  # type: ignore[attr-defined]
            str(governed_model_case.model_root),  # type: ignore[attr-defined]
            governed_model_case.model_id,  # type: ignore[attr-defined]
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert denied.returncode == 0, denied.stderr

    recovered = governed_model_case._installer().install(  # type: ignore[attr-defined]
        governed_model_case.model_id  # type: ignore[attr-defined]
    )
    recovered.close()
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    assert not governed_model_case.recovery_marker_exists  # type: ignore[attr-defined]
    assert governed_model_case.final_revision_is_complete_and_verified()  # type: ignore[attr-defined]


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
@pytest.mark.parametrize(
    "restoration_fault",
    ("create", "marker_fsync", "parent_fsync", "close"),
)
def test_marker_clear_restoration_fault_falls_back_to_cross_process_quarantine(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    restoration_fault: str,
) -> None:
    if phase == "recovery":
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
    model_path = (
        governed_model_case.model_root  # type: ignore[attr-defined]
        / governed_model_case.model_id  # type: ignore[attr-defined]
    )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    model_metadata = model_path.stat(follow_symlinks=False)
    model_identity = (model_metadata.st_dev, model_metadata.st_ino)
    primary = OSError("scripted marker-clear parent fsync failure")
    restoration_error = OSError(f"scripted marker restoration {restoration_fault} failure")
    marker_unlinked = False
    primary_injected = False
    faults_active = True
    restoration_attempts = 0
    restoration_close_attempts = 0
    real_unlink = os.unlink
    real_fsync = os.fsync
    real_close = os.close
    real_open_marker = ModelInstaller._open_recovery_marker

    def track_marker_unlink(path: str, *, dir_fd: int | None = None) -> None:
        nonlocal marker_unlinked
        real_unlink(path, dir_fd=dir_fd)
        if path == marker_path.name:
            marker_unlinked = True

    def fail_transaction_fsync(descriptor: int) -> None:
        nonlocal primary_injected
        nonlocal restoration_attempts
        identity = os.fstat(descriptor)
        descriptor_identity = (identity.st_dev, identity.st_ino)
        if (
            faults_active
            and marker_unlinked
            and descriptor_identity == model_identity
            and not primary_injected
        ):
            primary_injected = True
            raise primary
        if (
            faults_active
            and restoration_fault == "parent_fsync"
            and marker_unlinked
            and primary_injected
            and descriptor_identity == model_identity
        ):
            restoration_attempts += 1
            raise restoration_error
        if (
            faults_active
            and restoration_fault == "marker_fsync"
            and marker_unlinked
            and stat.S_ISREG(identity.st_mode)
            and stat.S_IMODE(identity.st_mode) == 0o600
            and identity.st_size == 0
        ):
            restoration_attempts += 1
            raise restoration_error
        real_fsync(descriptor)

    def fail_marker_restore_create(
        model: OwnedDirectory,
        revision: str,
        *,
        create: bool,
    ) -> int:
        nonlocal restoration_attempts
        if faults_active and marker_unlinked and restoration_fault == "create" and create:
            restoration_attempts += 1
            raise restoration_error
        return real_open_marker(model, revision, create=create)

    def fail_marker_restore_close(descriptor: int) -> None:
        nonlocal restoration_close_attempts
        is_restored_marker = False
        if faults_active and marker_unlinked and marker_path.exists():
            identity = os.fstat(descriptor)
            named = marker_path.stat(follow_symlinks=False)
            is_restored_marker = (identity.st_dev, identity.st_ino) == (
                named.st_dev,
                named.st_ino,
            )
        real_close(descriptor)
        if restoration_fault == "close" and is_restored_marker:
            restoration_close_attempts += 1
            raise restoration_error

    monkeypatch.setattr(os, "unlink", track_marker_unlink)
    monkeypatch.setattr(os, "fsync", fail_transaction_fsync)
    monkeypatch.setattr(os, "close", fail_marker_restore_close)
    monkeypatch.setattr(
        ModelInstaller,
        "_open_recovery_marker",
        staticmethod(fail_marker_restore_create),
    )

    caught: BaseException | None = None
    try:
        governed_model_case.install()  # type: ignore[attr-defined]
    except BaseException as error:
        caught = error
    faults_active = False

    assert caught is primary
    expected_note = (
        "additional descriptor cleanup failure"
        if restoration_fault == "close"
        else "additional recovery marker restoration failure"
    )
    assert getattr(primary, "__notes__", []) == [expected_note]
    assert restoration_attempts == (
        1
        if restoration_fault == "create"
        else 2
        if restoration_fault in {"marker_fsync", "parent_fsync"}
        else 0
    )
    assert restoration_close_attempts == (1 if restoration_fault == "close" else 0)
    expected_mode = 0o500 if phase == "fresh" and restoration_fault == "close" else 0o700
    assert governed_model_case.final_revision_mode == expected_mode  # type: ignore[attr-defined]
    assert governed_model_case.recovery_marker_exists is (  # type: ignore[attr-defined]
        restoration_fault != "create"
    )
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]

    denial_probe = (
        "from pathlib import Path\n"
        "import sys\n"
        "from tuntun_core.services.models.registry import ModelRegistry\n"
        "registry=ModelRegistry.load(Path(sys.argv[1]),model_root=Path(sys.argv[2]))\n"
        "try:\n"
        "    activated=registry.activate(sys.argv[3])\n"
        "except RuntimeError:\n"
        "    raise SystemExit(0)\n"
        "activated.close()\n"
        "raise SystemExit(1)\n"
    )
    denied = subprocess.run(
        [
            sys.executable,
            "-c",
            denial_probe,
            str(governed_model_case.manifest),  # type: ignore[attr-defined]
            str(governed_model_case.model_root),  # type: ignore[attr-defined]
            governed_model_case.model_id,  # type: ignore[attr-defined]
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert denied.returncode == 0, denied.stderr

    recovered = governed_model_case._installer().install(  # type: ignore[attr-defined]
        governed_model_case.model_id  # type: ignore[attr-defined]
    )
    recovered.close()
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    assert not governed_model_case.recovery_marker_exists  # type: ignore[attr-defined]
    assert governed_model_case.final_revision_is_complete_and_verified()  # type: ignore[attr-defined]
    available = subprocess.run(
        [
            sys.executable,
            "-c",
            denial_probe,
            str(governed_model_case.manifest),  # type: ignore[attr-defined]
            str(governed_model_case.model_root),  # type: ignore[attr-defined]
            governed_model_case.model_id,  # type: ignore[attr-defined]
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert available.returncode == 1, available.stderr


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
@pytest.mark.parametrize("rollback_fault", ("chmod", "fsync"))
def test_marker_restoration_and_mode_rollback_fault_reestablishes_quarantine(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    rollback_fault: str,
) -> None:
    if phase == "recovery":
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
    model_path = (
        governed_model_case.model_root  # type: ignore[attr-defined]
        / governed_model_case.model_id  # type: ignore[attr-defined]
    )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    model_metadata = model_path.stat(follow_symlinks=False)
    model_identity = (model_metadata.st_dev, model_metadata.st_ino)
    primary = OSError("scripted marker-clear parent fsync failure")
    restoration_error = OSError("scripted marker restoration create failure")
    rollback_error = OSError(f"scripted quarantine rollback {rollback_fault} failure")
    marker_unlinked = False
    primary_injected = False
    restoration_create_failed = False
    restoration_open_calls: list[bool] = []
    rollback_injected = False
    real_unlink = os.unlink
    real_fsync = OwnedDirectory.fsync
    real_chmod = OwnedDirectory.chmod
    real_open_marker = ModelInstaller._open_recovery_marker

    def track_marker_unlink(path: str, *, dir_fd: int | None = None) -> None:
        nonlocal marker_unlinked
        real_unlink(path, dir_fd=dir_fd)
        if path == marker_path.name:
            marker_unlinked = True

    def fail_clear_or_rollback_fsync(directory: OwnedDirectory) -> None:
        nonlocal primary_injected
        nonlocal rollback_injected
        identity = (directory.identity.device, directory.identity.inode)
        if marker_unlinked and identity == model_identity and not primary_injected:
            primary_injected = True
            raise primary
        if (
            rollback_fault == "fsync"
            and marker_unlinked
            and identity != model_identity
            and stat.S_IMODE(os.fstat(directory.fd).st_mode) == 0o700
            and not rollback_injected
        ):
            rollback_injected = True
            raise rollback_error
        real_fsync(directory)

    def fail_rollback_chmod(directory: OwnedDirectory, mode: int) -> None:
        nonlocal rollback_injected
        identity = (directory.identity.device, directory.identity.inode)
        if (
            rollback_fault == "chmod"
            and marker_unlinked
            and identity != model_identity
            and mode == 0o700
            and not rollback_injected
        ):
            rollback_injected = True
            raise rollback_error
        real_chmod(directory, mode)

    def fail_first_restore_create(
        model: OwnedDirectory,
        revision: str,
        *,
        create: bool,
    ) -> int:
        nonlocal restoration_create_failed
        if marker_unlinked:
            restoration_open_calls.append(create)
        if marker_unlinked and create and not restoration_create_failed:
            restoration_create_failed = True
            raise restoration_error
        return real_open_marker(model, revision, create=create)

    monkeypatch.setattr(os, "unlink", track_marker_unlink)
    monkeypatch.setattr(OwnedDirectory, "fsync", fail_clear_or_rollback_fsync)
    monkeypatch.setattr(OwnedDirectory, "chmod", fail_rollback_chmod)
    monkeypatch.setattr(
        ModelInstaller,
        "_open_recovery_marker",
        staticmethod(fail_first_restore_create),
    )

    caught: BaseException | None = None
    try:
        governed_model_case.install()  # type: ignore[attr-defined]
    except BaseException as error:
        caught = error

    assert caught is primary
    assert restoration_create_failed
    assert restoration_open_calls == [True, False, True]
    assert rollback_injected
    assert getattr(primary, "__notes__", []) == [
        "additional recovery marker restoration failure",
        "additional recovery rollback failure",
    ]
    expected_mode = 0o500 if rollback_fault == "chmod" else 0o700
    assert governed_model_case.final_revision_mode == expected_mode  # type: ignore[attr-defined]
    assert governed_model_case.recovery_marker_exists  # type: ignore[attr-defined]
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]

    denial_probe = (
        "from pathlib import Path\n"
        "import sys\n"
        "from tuntun_core.services.models.registry import ModelRegistry\n"
        "registry=ModelRegistry.load(Path(sys.argv[1]),model_root=Path(sys.argv[2]))\n"
        "try:\n"
        "    activated=registry.activate(sys.argv[3])\n"
        "except RuntimeError:\n"
        "    raise SystemExit(0)\n"
        "activated.close()\n"
        "raise SystemExit(1)\n"
    )
    denied = subprocess.run(
        [
            sys.executable,
            "-c",
            denial_probe,
            str(governed_model_case.manifest),  # type: ignore[attr-defined]
            str(governed_model_case.model_root),  # type: ignore[attr-defined]
            governed_model_case.model_id,  # type: ignore[attr-defined]
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert denied.returncode == 0, denied.stderr

    governed_model_case.restart_and_reconcile()  # type: ignore[attr-defined]
    assert governed_model_case.final_revision_is_complete_and_verified()  # type: ignore[attr-defined]


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
def test_total_quarantine_fallback_exhaustion_requires_positive_commit_proof(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    if phase == "recovery":
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
    model_path = (
        governed_model_case.model_root  # type: ignore[attr-defined]
        / governed_model_case.model_id  # type: ignore[attr-defined]
    )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    commit_path = model_path / f".publication-verified-{'a' * 40}"
    model_metadata = model_path.stat(follow_symlinks=False)
    model_identity = (model_metadata.st_dev, model_metadata.st_ino)
    primary = OSError("scripted marker-clear parent fsync failure")
    restoration_error = OSError("scripted total marker restoration failure")
    rollback_error = OSError("scripted total rollback chmod failure")
    marker_unlinked = False
    primary_injected = False
    faults_active = True
    restoration_open_calls: list[bool] = []
    rollback_attempts = 0
    real_unlink = os.unlink
    real_fsync = OwnedDirectory.fsync
    real_chmod = OwnedDirectory.chmod
    real_open_marker = ModelInstaller._open_recovery_marker

    def track_marker_unlink(path: str, *, dir_fd: int | None = None) -> None:
        nonlocal marker_unlinked
        real_unlink(path, dir_fd=dir_fd)
        if path == marker_path.name:
            marker_unlinked = True

    def fail_clear_parent_fsync(directory: OwnedDirectory) -> None:
        nonlocal primary_injected
        identity = (directory.identity.device, directory.identity.inode)
        if (
            faults_active
            and marker_unlinked
            and identity == model_identity
            and not primary_injected
        ):
            primary_injected = True
            raise primary
        real_fsync(directory)

    def fail_rollback_chmod(directory: OwnedDirectory, mode: int) -> None:
        nonlocal rollback_attempts
        identity = (directory.identity.device, directory.identity.inode)
        if faults_active and marker_unlinked and identity != model_identity and mode == 0o700:
            rollback_attempts += 1
            raise rollback_error
        real_chmod(directory, mode)

    def fail_every_marker_restore(
        model: OwnedDirectory,
        revision: str,
        *,
        create: bool,
    ) -> int:
        if faults_active and marker_unlinked:
            restoration_open_calls.append(create)
            if create:
                raise restoration_error
        return real_open_marker(model, revision, create=create)

    monkeypatch.setattr(os, "unlink", track_marker_unlink)
    monkeypatch.setattr(OwnedDirectory, "fsync", fail_clear_parent_fsync)
    monkeypatch.setattr(OwnedDirectory, "chmod", fail_rollback_chmod)
    monkeypatch.setattr(
        ModelInstaller,
        "_open_recovery_marker",
        staticmethod(fail_every_marker_restore),
    )

    caught: BaseException | None = None
    try:
        governed_model_case.install()  # type: ignore[attr-defined]
    except BaseException as error:
        caught = error

    assert caught is primary
    assert primary_injected
    assert restoration_open_calls == [True, False, True, False]
    assert rollback_attempts == 1
    assert getattr(primary, "__notes__", []) == [
        "additional recovery marker restoration failure",
        "additional recovery rollback failure",
        "additional recovery marker restoration failure",
    ]
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    assert not governed_model_case.recovery_marker_exists  # type: ignore[attr-defined]
    assert not commit_path.exists()
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]

    activation_probe = (
        "from pathlib import Path\n"
        "import sys\n"
        "from tuntun_core.services.models.registry import ModelRegistry\n"
        "registry=ModelRegistry.load(Path(sys.argv[1]),model_root=Path(sys.argv[2]))\n"
        "try:\n"
        "    activated=registry.activate(sys.argv[3])\n"
        "except RuntimeError:\n"
        "    raise SystemExit(0)\n"
        "activated.close()\n"
        "raise SystemExit(1)\n"
    )
    denied = subprocess.run(
        [
            sys.executable,
            "-c",
            activation_probe,
            str(governed_model_case.manifest),  # type: ignore[attr-defined]
            str(governed_model_case.model_root),  # type: ignore[attr-defined]
            governed_model_case.model_id,  # type: ignore[attr-defined]
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert denied.returncode == 0, denied.stderr

    faults_active = False
    governed_model_case.clear_process_publication_uncertainty()  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError, match="model is not installed and verified"):
        ModelRegistry.load(
            governed_model_case.manifest,  # type: ignore[attr-defined]
            model_root=governed_model_case.model_root,  # type: ignore[attr-defined]
        ).activate(governed_model_case.model_id)  # type: ignore[attr-defined]

    recovered = governed_model_case._installer().install(  # type: ignore[attr-defined]
        governed_model_case.model_id  # type: ignore[attr-defined]
    )
    recovered.close()
    assert commit_path.exists()
    assert governed_model_case.final_revision_is_complete_and_verified()  # type: ignore[attr-defined]

    available = subprocess.run(
        [
            sys.executable,
            "-c",
            activation_probe,
            str(governed_model_case.manifest),  # type: ignore[attr-defined]
            str(governed_model_case.model_root),  # type: ignore[attr-defined]
            governed_model_case.model_id,  # type: ignore[attr-defined]
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert available.returncode == 1, available.stderr


def test_activation_rechecks_publication_uncertainty_after_verification(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed = governed_model_case.install()  # type: ignore[attr-defined]
    installed.close()
    model_path = (
        governed_model_case.model_root  # type: ignore[attr-defined]
        / governed_model_case.model_id  # type: ignore[attr-defined]
    )
    revision = "a" * 40
    real_hash = registry_module.hash_exact_fd
    uncertainty_marked = False

    def mark_uncertain_during_verification(
        descriptor: int,
        size: int,
        expected_sha256: str,
    ) -> str:
        nonlocal uncertainty_marked
        if not uncertainty_marked:
            model = OwnedDirectory.open(model_path)
            try:
                fs_module._mark_publication_uncertain(model, revision)
            finally:
                model.close()
            uncertainty_marked = True
        return real_hash(descriptor, size, expected_sha256)

    monkeypatch.setattr(registry_module, "hash_exact_fd", mark_uncertain_during_verification)

    try:
        with pytest.raises(RuntimeError) as caught:
            ModelRegistry.load(
                governed_model_case.manifest,  # type: ignore[attr-defined]
                model_root=governed_model_case.model_root,  # type: ignore[attr-defined]
            ).activate(governed_model_case.model_id)  # type: ignore[attr-defined]
        assert uncertainty_marked
        assert isinstance(caught.value.__cause__, PermissionError)
        assert str(caught.value.__cause__) == "model revision commit is uncertain"
        assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]
    finally:
        governed_model_case.clear_process_publication_uncertainty()  # type: ignore[attr-defined]


@pytest.mark.parametrize("durability_fault", ("marker_fsync", "parent_fsync"))
@pytest.mark.parametrize("initial_mode", (0o700, 0o500), ids=("unsealed", "sealed"))
def test_existing_marker_is_redurably_synced_before_recovery(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    durability_fault: str,
    initial_mode: int,
) -> None:
    if initial_mode == 0o500:
        governed_model_case.create_sealed_pending_revision()  # type: ignore[attr-defined]
    else:
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
        governed_model_case.create_interrupted_recovery_marker()  # type: ignore[attr-defined]
    model_path = (
        governed_model_case.model_root  # type: ignore[attr-defined]
        / governed_model_case.model_id  # type: ignore[attr-defined]
    )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    model_metadata = model_path.stat(follow_symlinks=False)
    marker_metadata = marker_path.stat(follow_symlinks=False)
    model_identity = (model_metadata.st_dev, model_metadata.st_ino)
    marker_identity = (marker_metadata.st_dev, marker_metadata.st_ino)
    primary = OSError(f"scripted existing {durability_fault} failure")
    secondary = OSError("scripted marker cleanup close failure")
    marker_fsync_attempts = 0
    parent_fsync_attempts = 0
    marker_synced = False
    fault_injected = False
    marker_descriptors: set[int] = set()
    marker_close_attempts: list[int] = []
    close_fault_injected = False
    real_fsync = os.fsync
    real_close = os.close

    def fail_durability_fsync(descriptor: int) -> None:
        nonlocal marker_fsync_attempts
        nonlocal parent_fsync_attempts
        nonlocal marker_synced
        nonlocal fault_injected
        identity = os.fstat(descriptor)
        descriptor_identity = (identity.st_dev, identity.st_ino)
        if descriptor_identity == marker_identity:
            marker_descriptors.add(descriptor)
            marker_fsync_attempts += 1
            if durability_fault == "marker_fsync" and not fault_injected:
                fault_injected = True
                raise primary
            real_fsync(descriptor)
            marker_synced = True
            return
        if descriptor_identity == model_identity and marker_synced:
            parent_fsync_attempts += 1
            if durability_fault == "parent_fsync" and not fault_injected:
                fault_injected = True
                raise primary
        real_fsync(descriptor)

    def track_marker_close(descriptor: int) -> None:
        nonlocal close_fault_injected
        if descriptor in marker_descriptors:
            marker_close_attempts.append(descriptor)
        real_close(descriptor)
        if descriptor in marker_descriptors and not close_fault_injected:
            close_fault_injected = True
            raise secondary

    monkeypatch.setattr(os, "fsync", fail_durability_fsync)
    monkeypatch.setattr(os, "close", track_marker_close)

    caught: BaseException | None = None
    try:
        unexpected = governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
    except BaseException as error:
        caught = error
    else:
        unexpected.close()

    assert isinstance(caught, PermissionError)
    assert caught.__cause__ is primary
    assert getattr(primary, "__notes__", []) == ["additional descriptor cleanup failure"]
    assert marker_fsync_attempts == 1
    assert parent_fsync_attempts == (1 if durability_fault == "parent_fsync" else 0)
    assert len(marker_close_attempts) == 1
    assert governed_model_case.final_revision_mode == 0o700  # type: ignore[attr-defined]
    assert governed_model_case.recovery_marker_exists  # type: ignore[attr-defined]
    assert not governed_model_case.final_revision_is_complete_and_verified()  # type: ignore[attr-defined]
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]

    governed_model_case.restart_and_reconcile()  # type: ignore[attr-defined]
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    assert not governed_model_case.recovery_marker_exists  # type: ignore[attr-defined]
    assert governed_model_case.final_revision_is_complete_and_verified()  # type: ignore[attr-defined]


@pytest.mark.parametrize("identity_fault", ("swap", "disappearance"))
@pytest.mark.parametrize("initial_mode", (0o700, 0o500), ids=("unsealed", "sealed"))
def test_existing_marker_identity_is_revalidated_after_parent_fsync_before_recovery(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    identity_fault: str,
    initial_mode: int,
) -> None:
    if initial_mode == 0o500:
        governed_model_case.create_sealed_pending_revision()  # type: ignore[attr-defined]
    else:
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
        governed_model_case.create_interrupted_recovery_marker()  # type: ignore[attr-defined]
    model_path = (
        governed_model_case.model_root  # type: ignore[attr-defined]
        / governed_model_case.model_id  # type: ignore[attr-defined]
    )
    revision_path = model_path / ("a" * 40)
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    model_metadata = model_path.stat(follow_symlinks=False)
    revision_metadata = revision_path.stat(follow_symlinks=False)
    marker_metadata = marker_path.stat(follow_symlinks=False)
    model_identity = (model_metadata.st_dev, model_metadata.st_ino)
    revision_identity = (revision_metadata.st_dev, revision_metadata.st_ino)
    marker_identity = (marker_metadata.st_dev, marker_metadata.st_ino)
    model_fsyncs = 0
    marker_mutated = False
    seal_attempts = 0
    marker_close_attempts = 0
    real_fsync = OwnedDirectory.fsync
    real_chmod = OwnedDirectory.chmod
    real_close = os.close

    def mutate_marker_after_durability_fsync(directory: OwnedDirectory) -> None:
        nonlocal model_fsyncs
        nonlocal marker_mutated
        real_fsync(directory)
        identity = (directory.identity.device, directory.identity.inode)
        if identity != model_identity:
            return
        model_fsyncs += 1
        if model_fsyncs == 2 and not marker_mutated:
            marker_path.unlink()
            if identity_fault == "swap":
                marker_path.write_bytes(b"")
                marker_path.chmod(0o600)
            marker_mutated = True

    def track_seal(directory: OwnedDirectory, mode: int) -> None:
        nonlocal seal_attempts
        identity = (directory.identity.device, directory.identity.inode)
        if identity == revision_identity and mode == 0o500:
            seal_attempts += 1
        real_chmod(directory, mode)

    def track_marker_close(descriptor: int) -> None:
        nonlocal marker_close_attempts
        identity = os.fstat(descriptor)
        if (identity.st_dev, identity.st_ino) == marker_identity:
            marker_close_attempts += 1
        real_close(descriptor)

    monkeypatch.setattr(OwnedDirectory, "fsync", mutate_marker_after_durability_fsync)
    monkeypatch.setattr(OwnedDirectory, "chmod", track_seal)
    monkeypatch.setattr(os, "close", track_marker_close)

    with pytest.raises(PermissionError) as caught:
        governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )

    assert isinstance(caught.value.__cause__, (FileNotFoundError, PermissionError))
    assert marker_mutated
    assert seal_attempts == 0
    assert marker_close_attempts == 1
    assert governed_model_case.final_revision_mode == 0o700  # type: ignore[attr-defined]
    assert governed_model_case.recovery_marker_exists is (  # type: ignore[attr-defined]
        identity_fault == "swap"
    )
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]

    governed_model_case.restart_and_reconcile()  # type: ignore[attr-defined]
    assert not governed_model_case.recovery_marker_exists  # type: ignore[attr-defined]
    assert governed_model_case.final_revision_is_complete_and_verified()  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "fault",
    (
        "after_each_file",
        "before_stage_fsync",
        "after_stage_fsync",
        "before_publish",
        "after_publish_before_parent_fsync",
    ),
)
def test_crash_or_error_never_exposes_a_mixed_revision(
    governed_model_case: object,
    fault: str,
) -> None:
    governed_model_case.crash_install_at(fault)  # type: ignore[attr-defined]
    governed_model_case.restart_and_reconcile()  # type: ignore[attr-defined]
    assert governed_model_case.final_revision_is_absent_or_complete_and_verified()  # type: ignore[attr-defined]
    assert governed_model_case.previous_revision_unchanged()  # type: ignore[attr-defined]


@pytest.mark.parametrize("command", (("list",), ("verify",)))
def test_non_install_model_cli_commands_never_open_network(
    monkeypatch: pytest.MonkeyPatch,
    command: tuple[str, ...],
) -> None:
    def blocked_socket(*_args: object, **_kwargs: object) -> socket.socket:
        raise AssertionError("model CLI attempted network I/O")

    monkeypatch.setattr(socket, "socket", blocked_socket)
    result = CliRunner().invoke(app, ["models", *command])
    assert result.exit_code == 0, result.output
    assert result.stdout == "[]\n"


def test_installed_cli_uses_the_packaged_governed_manifest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    missing_repository_manifest = tmp_path / "missing.yaml"
    packaged_manifest = tmp_path / "packaged.yaml"
    packaged_manifest.write_text('schema_version: "1.0"\nmodels: []\n', encoding="utf-8")
    monkeypatch.setattr(models_command, "_REPOSITORY_MANIFEST", missing_repository_manifest)
    monkeypatch.setattr(models_command, "_PACKAGED_MANIFEST", packaged_manifest)
    assert models_command._manifest_path() == packaged_manifest

    packaged_source = Path("apps/core/src/tuntun_core/resources/model-manifest.yaml")
    assert packaged_source.read_bytes() == Path("models/manifest.yaml").read_bytes()
