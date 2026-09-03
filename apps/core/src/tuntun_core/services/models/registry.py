from __future__ import annotations

import contextlib
import fcntl
import hashlib
import os
import re
import stat
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import NoReturn, Protocol
from urllib.parse import urlsplit

from .fs import (
    OwnedDirectory,
    _FileDescriptorOwner,
    _FileDescriptorOwnerSlot,
    _OwnedDirectoryOwnerSlot,
    close_preserving_primary,
    entry_exists_at,
    hash_exact_fd,
    model_install_lock_name,
    open_publication_commit,
    open_regular_at,
    read_bounded_strict_yaml,
    recovery_pending_name,
    require_publication_commit,
)

SAFE_SUFFIXES = {".json", ".onnx", ".safetensors", ".tflite", ".txt"}
MODEL_ID = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
REVISION = re.compile(r"^[0-9a-f]{40,64}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
FILE_PATH = re.compile(r"^[A-Za-z0-9_.-]+\.(?:onnx|json|txt|tflite|safetensors)$")
MODEL_URL = re.compile(r"^https://[^/?#:@]+(?::443)?(?:/[^?#]*)$")
CALIBRATION_REPORT_PATH = "calibration-report.json"
MAX_MODEL_FILE_BYTES = 4_000_000_000
MAX_MODEL_REVISION_BYTES = 8_000_000_000
MAX_MODEL_FILES = 64
MAX_MODELS = 256
_TASK12_LOCAL_INFERENCE_MODEL_IDS = frozenset({"hello-tuntun-v1", "stop-tuntun-v1"})
_TASK12_METADATA_KEYS = frozenset({"calibration_report_sha256", "runtime_download"})
_BASE_ENTRY_KEYS = frozenset(
    {
        "id",
        "revision",
        "license",
        "provenance",
        "redistribution",
        "approved_purpose",
        "runtime",
        "architecture",
        "input_contract",
        "output_contract",
        "benchmark_gate",
        "review_date",
        "files",
    }
)
_ENTRY_KEYS = _BASE_ENTRY_KEYS | _TASK12_METADATA_KEYS
_FILE_KEYS = frozenset({"path", "size", "sha256", "url"})


class ModelVerificationError(PermissionError):
    pass


class LocalInferenceUnavailableError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("local-inference-runtime-unavailable")


@dataclass(frozen=True, slots=True)
class ModelFile:
    path: str
    size: int
    sha256: str
    url: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.path, str)
            or type(self.size) is not int
            or not isinstance(self.sha256, str)
            or not isinstance(self.url, str)
        ):
            raise ValueError("invalid model manifest")
        try:
            parsed = urlsplit(self.url)
            parsed_port = parsed.port
        except ValueError as error:
            raise ValueError("invalid model manifest") from error
        if (
            Path(self.path).name != self.path
            or self.path in {"", ".", ".."}
            or len(self.path) > 255
            or "\x00" in self.path
            or FILE_PATH.fullmatch(self.path) is None
            or Path(self.path).suffix not in SAFE_SUFFIXES
            or not 1 <= self.size <= MAX_MODEL_FILE_BYTES
            or DIGEST.fullmatch(self.sha256) is None
            or MODEL_URL.fullmatch(self.url) is None
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed_port not in {None, 443}
            or parsed.query
            or parsed.fragment
            or not parsed.path.startswith("/")
            or len(self.url) > 4096
        ):
            raise ValueError("invalid model manifest")


@dataclass(frozen=True, slots=True)
class ModelEntry:
    model_id: str
    revision: str
    license: str
    provenance: str
    redistribution: str
    approved_purpose: str
    runtime: str
    architecture: str
    input_contract: str
    output_contract: str
    benchmark_gate: str
    calibration_report_sha256: str | None
    runtime_download: bool | None
    review_date: str
    files: tuple[ModelFile, ...]

    def __post_init__(self) -> None:
        scalar_values = (
            self.model_id,
            self.revision,
            self.license,
            self.provenance,
            self.redistribution,
            self.approved_purpose,
            self.runtime,
            self.architecture,
            self.input_contract,
            self.output_contract,
            self.benchmark_gate,
            self.review_date,
        )
        names = tuple(item.path for item in self.files)
        metadata_present = (
            self.calibration_report_sha256 is not None or self.runtime_download is not None
        )
        task12_model = self.model_id in _TASK12_LOCAL_INFERENCE_MODEL_IDS
        task12_metadata_invalid = metadata_present and (
            not isinstance(self.calibration_report_sha256, str)
            or DIGEST.fullmatch(self.calibration_report_sha256) is None
            or self.runtime_download is not False
        )
        calibration_files = tuple(
            item for item in self.files if item.path == CALIBRATION_REPORT_PATH
        )
        if (
            any(not isinstance(value, str) for value in scalar_values)
            or MODEL_ID.fullmatch(self.model_id) is None
            or REVISION.fullmatch(self.revision) is None
            or task12_metadata_invalid
            or (not metadata_present and task12_model)
            or (
                metadata_present
                and (
                    len(calibration_files) != 1
                    or calibration_files[0].sha256 != self.calibration_report_sha256
                )
            )
            or not 1 <= len(self.files) <= MAX_MODEL_FILES
            or len(set(names)) != len(names)
            or sum(item.size for item in self.files) > MAX_MODEL_REVISION_BYTES
            or any(not value or len(value) > 4096 for value in scalar_values[2:])
        ):
            raise ValueError("invalid model manifest")


@dataclass(frozen=True, slots=True)
class RuntimeFileReceipt:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class RuntimeModelReceipt:
    signature_domain: str
    key_generation: int
    expires_at: int
    model_id: str
    revision: str
    files: tuple[RuntimeFileReceipt, ...]
    signature: str
    loaded_sha256: str


class RuntimeAdapter(Protocol):
    def load_verified_reader(
        self, reader: PreadOnlyModelReader, path: str, size: int, sha256: str
    ) -> RuntimeFileReceipt: ...

    def finish_model(
        self, model_id: str, revision: str, receipts: tuple[RuntimeFileReceipt, ...]
    ) -> RuntimeModelReceipt: ...

    def abort_model(
        self, model_id: str, revision: str, receipts: tuple[RuntimeFileReceipt, ...]
    ) -> None: ...


class ReceiptVerifier(Protocol):
    def require_exact_signed_current(
        self,
        candidate: RuntimeModelReceipt,
        *,
        signature_domain: str,
        model_id: str,
        revision: str,
        files: tuple[tuple[str, int, str], ...],
    ) -> RuntimeModelReceipt: ...


class _PreadOnlyModelReaderOwnerSlot:
    __slots__ = ("owner",)

    def __init__(self) -> None:
        self.owner: PreadOnlyModelReader | None = None


class PreadOnlyModelReader:
    __slots__ = (
        "__closed",
        "__digest",
        "__expected_sha256",
        "__descriptor_owner",
        "__next_offset",
        "size",
    )

    def __init__(
        self,
        descriptor_owner: _FileDescriptorOwner,
        size: int,
        expected_sha256: str,
    ) -> None:
        self.__descriptor_owner = descriptor_owner
        self.size = size
        self.__closed = False
        self.__next_offset = 0
        self.__digest = hashlib.sha256()
        self.__expected_sha256 = expected_sha256

    @classmethod
    def from_descriptor_owner(
        cls,
        descriptor_slot: _FileDescriptorOwnerSlot,
        owner_slot: _PreadOnlyModelReaderOwnerSlot,
        size: int,
        expected_sha256: str,
    ) -> None:
        if owner_slot.owner is not None:
            raise ValueError("model reader owner slot already populated")
        descriptor_owner = descriptor_slot.owner
        if descriptor_owner is None:
            raise ValueError("model reader descriptor owner missing")
        owner_slot.owner = cls(descriptor_owner, size, expected_sha256)
        descriptor_slot.owner = None

    @property
    def closed(self) -> bool:
        return self.__closed

    def read_at(self, offset: int, length: int) -> bytes:
        if self.__closed:
            raise ValueError("model reader is closed")
        if (
            type(offset) is not int
            or type(length) is not int
            or not 0 <= offset <= self.size
            or not 1 <= length <= 1_048_576
            or offset != self.__next_offset
        ):
            raise ValueError("invalid model reader range")
        chunk = os.pread(
            self.__descriptor_owner.fileno(),
            min(length, self.size - offset),
            offset,
        )
        self.__digest.update(chunk)
        self.__next_offset += len(chunk)
        return chunk

    def chunks(self, chunk_size: int = 1_048_576) -> Iterator[bytes]:
        if type(chunk_size) is not int or not 1 <= chunk_size <= 1_048_576:
            raise ValueError("invalid model reader range")
        while self.__next_offset < self.size:
            chunk = self.read_at(self.__next_offset, chunk_size)
            if not chunk:
                raise RuntimeError("model descriptor truncated")
            yield chunk

    def require_complete(self) -> None:
        if self.__next_offset != self.size or self.__digest.hexdigest() != self.__expected_sha256:
            raise ModelVerificationError("runtime model reader incomplete")

    def close(self) -> None:
        if not self.__closed:
            self.__descriptor_owner.close()
            self.__closed = True


@dataclass(frozen=True, slots=True)
class _ManifestBoundFile:
    path: str
    size: int
    sha256: str
    device: int
    inode: int


class _VerifiedModelFileOwnerSlot:
    __slots__ = ("owner",)

    def __init__(self) -> None:
        self.owner: VerifiedModelFile | None = None


@dataclass(frozen=True)
class VerifiedModelFile:
    __descriptor_owner: _FileDescriptorOwner
    __expected: _ManifestBoundFile
    __lock: threading.Lock = field(default_factory=threading.Lock, compare=False, repr=False)

    @classmethod
    def from_manifest(
        cls,
        item: ModelFile,
        descriptor_slot: _FileDescriptorOwnerSlot,
        owner_slot: _VerifiedModelFileOwnerSlot,
    ) -> None:
        if owner_slot.owner is not None:
            raise ValueError("verified model file owner slot already populated")
        descriptor_owner = descriptor_slot.owner
        if descriptor_owner is None:
            raise ValueError("verified model descriptor owner missing")
        metadata = os.fstat(descriptor_owner.fileno())
        owner_slot.owner = cls(
            descriptor_owner,
            _ManifestBoundFile(item.path, item.size, item.sha256, metadata.st_dev, metadata.st_ino),
        )
        descriptor_slot.owner = None

    @property
    def path(self) -> str:
        return self.__expected.path

    @property
    def size(self) -> int:
        return self.__expected.size

    @property
    def sha256(self) -> str:
        return self.__expected.sha256

    @property
    def fd(self) -> int:
        with self.__lock:
            try:
                descriptor = self.__descriptor_owner.fileno()
            except OSError as error:
                raise ModelVerificationError("verified model file is closed") from error
            if descriptor < 0:
                raise ModelVerificationError("verified model file is closed")
            return descriptor

    def _duplicate(self, owner_slot: _FileDescriptorOwnerSlot) -> None:
        if owner_slot.owner is not None:
            raise ValueError("duplicate descriptor owner slot already populated")
        with self.__lock:
            try:
                descriptor = self.__descriptor_owner.fileno()
            except OSError as error:
                raise ModelVerificationError("verified model file is closed") from error
            owner_slot.owner = _FileDescriptorOwner()
            owner_slot.owner.duplicate(descriptor)

    def verified(self) -> bool:
        duplicate_slot = _FileDescriptorOwnerSlot()
        try:
            self._duplicate(duplicate_slot)
            duplicate_owner = duplicate_slot.owner
            if duplicate_owner is None:
                raise RuntimeError("duplicate descriptor acquisition missing")
            duplicate = duplicate_owner.fileno()
            metadata = os.fstat(duplicate)
            if (
                fcntl.fcntl(duplicate, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o400
                or (metadata.st_dev, metadata.st_ino)
                != (self.__expected.device, self.__expected.inode)
                or metadata.st_size != self.__expected.size
            ):
                return False
            hash_exact_fd(duplicate, self.__expected.size, self.__expected.sha256)
        except (OSError, PermissionError, ValueError):
            return False
        finally:
            if duplicate_slot.owner is not None:
                duplicate_slot.owner.close()
        return True

    def load_with(self, adapter: RuntimeAdapter) -> RuntimeFileReceipt:
        duplicate_slot = _FileDescriptorOwnerSlot()
        reader_slot = _PreadOnlyModelReaderOwnerSlot()
        try:
            self._duplicate(duplicate_slot)
            duplicate_owner = duplicate_slot.owner
            if duplicate_owner is None:
                raise RuntimeError("duplicate descriptor acquisition missing")
            duplicate = duplicate_owner.fileno()
            duplicate_metadata = os.fstat(duplicate)
            if fcntl.fcntl(duplicate, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY or (
                duplicate_metadata.st_dev,
                duplicate_metadata.st_ino,
            ) != (self.__expected.device, self.__expected.inode):
                raise ModelVerificationError("runtime model descriptor mismatch")
            hash_exact_fd(duplicate, self.__expected.size, self.__expected.sha256)
            PreadOnlyModelReader.from_descriptor_owner(
                duplicate_slot,
                reader_slot,
                self.__expected.size,
                self.__expected.sha256,
            )
            reader = reader_slot.owner
            if reader is None:
                raise RuntimeError("model reader acquisition missing")
            receipt = adapter.load_verified_reader(
                reader,
                self.__expected.path,
                self.__expected.size,
                self.__expected.sha256,
            )
            reader.require_complete()
            return receipt
        finally:
            if duplicate_slot.owner is not None:
                duplicate_slot.owner.close()
            if reader_slot.owner is not None:
                reader_slot.owner.close()

    def close(self) -> None:
        with self.__lock:
            self.__descriptor_owner.close()


@dataclass(frozen=True)
class ActivatedModel:
    model_id: str
    revision: str
    runtime_download: bool | None
    calibration_report_sha256: str | None
    __files: tuple[VerifiedModelFile, ...]
    __manifest_files: tuple[tuple[str, int, str], ...]
    __closed: list[bool] = field(default_factory=lambda: [False], compare=False, repr=False)
    __lock: threading.RLock = field(default_factory=threading.RLock, compare=False, repr=False)

    @classmethod
    def from_manifest(
        cls,
        entry: ModelEntry,
        files: tuple[VerifiedModelFile, ...],
        owner_slot: _ActivatedModelOwnerSlot,
    ) -> None:
        if owner_slot.owner is not None:
            raise ValueError("activated model owner slot already populated")
        expected = tuple((item.path, item.size, item.sha256) for item in entry.files)
        observed = tuple((item.path, item.size, item.sha256) for item in files)
        if not files or observed != expected:
            raise ModelVerificationError("activated model is not manifest-bound")
        owner_slot.owner = cls(
            entry.model_id,
            entry.revision,
            entry.runtime_download,
            entry.calibration_report_sha256,
            files,
            expected,
        )

    @property
    def files(self) -> tuple[VerifiedModelFile, ...]:
        return self.__files

    @property
    def all_files_verified(self) -> bool:
        with self.__lock:
            return (
                not self.__closed[0]
                and bool(self.__files)
                and all(item.verified() for item in self.__files)
            )

    def unavailable_local_inference_handle(
        self,
        *,
        expected_model_id: str,
    ) -> UnavailableLocalInferenceHandle:
        with self.__lock:
            calibration_files = tuple(
                item for item in self.__manifest_files if item[0] == CALIBRATION_REPORT_PATH
            )
            if (
                type(expected_model_id) is not str
                or self.__closed[0]
                or self.model_id != expected_model_id
                or self.runtime_download is not False
                or self.calibration_report_sha256 is None
                or len(calibration_files) != 1
                or calibration_files[0][2] != self.calibration_report_sha256
                or not self.all_files_verified
            ):
                raise ModelVerificationError("local inference unavailable")
            return UnavailableLocalInferenceHandle(
                self,
                self.model_id,
                False,
                self.calibration_report_sha256,
            )

    def load_with(
        self, adapter: RuntimeAdapter, receipt_verifier: ReceiptVerifier
    ) -> RuntimeModelReceipt:
        with self.__lock:
            if self.__closed[0]:
                raise ModelVerificationError("activated model is closed")
            receipts: list[RuntimeFileReceipt] = []
            try:
                if not bool(self.__files) or not all(item.verified() for item in self.__files):
                    raise ModelVerificationError("activated model descriptor mismatch")
                for item in self.__files:
                    receipts.append(item.load_with(adapter))
                try:
                    observed = tuple((item.path, item.size, item.sha256) for item in receipts)
                except (AttributeError, TypeError, ValueError) as error:
                    raise ModelVerificationError("runtime model receipt mismatch") from error
                if observed != self.__manifest_files:
                    raise ModelVerificationError("runtime model receipt mismatch")
                candidate = adapter.finish_model(self.model_id, self.revision, tuple(receipts))
                try:
                    return receipt_verifier.require_exact_signed_current(
                        candidate,
                        signature_domain="tuntun.runtime-model-loader-receipt.v1",
                        model_id=self.model_id,
                        revision=self.revision,
                        files=self.__manifest_files,
                    )
                except BaseException as error:
                    raise ModelVerificationError("runtime model receipt mismatch") from error
            except BaseException:
                try:
                    adapter.abort_model(self.model_id, self.revision, tuple(receipts))
                except BaseException as abort_error:
                    raise RuntimeError(
                        "runtime model abort failed; disable capability"
                    ) from abort_error
                raise

    def close(self) -> None:
        with self.__lock:
            if self.__closed[0]:
                return
            for item in self.__files:
                with contextlib.suppress(OSError):
                    item.close()
            self.__closed[0] = True


@dataclass(frozen=True, slots=True)
class UnavailableLocalInferenceHandle:
    _activation: ActivatedModel = field(compare=False, repr=False)
    model_id: str
    runtime_download: bool
    calibration_report_sha256: str

    @property
    def activated(self) -> bool:
        return self._activation.all_files_verified

    def _raise_unavailable(self) -> NoReturn:
        if not self.activated:
            raise ModelVerificationError("local inference unavailable")
        raise LocalInferenceUnavailableError()

    def infer_score(self, _frame: bytes) -> int:
        self._raise_unavailable()

    def infer_voice_score(self, _frame: bytes) -> int:
        self._raise_unavailable()


class _ActivatedModelOwnerSlot:
    """Transaction-visible ownership for one unreturned activated model."""

    __slots__ = ("owner",)

    def __init__(self) -> None:
        self.owner: ActivatedModel | None = None


class ModelRegistry:
    def __init__(self, entries: dict[str, ModelEntry], model_root: Path) -> None:
        self._entries = dict(entries)
        self._root = model_root

    @classmethod
    def load(cls, manifest: Path, model_root: Path = Path("var/models")) -> ModelRegistry:
        return cls.from_document(read_bounded_strict_yaml(manifest), model_root=model_root)

    @classmethod
    def from_document(cls, raw: object, *, model_root: Path = Path("var/models")) -> ModelRegistry:
        if (
            not isinstance(raw, dict)
            or set(raw) != {"schema_version", "models"}
            or raw.get("schema_version") != "1.0"
        ):
            raise ValueError("invalid model manifest")
        raw_models = raw.get("models")
        if not isinstance(raw_models, list) or len(raw_models) > MAX_MODELS:
            raise ValueError("invalid model manifest")
        entries: dict[str, ModelEntry] = {}
        for raw_entry in raw_models:
            if not isinstance(raw_entry, dict):
                raise ValueError("invalid model manifest")
            entry_keys = frozenset(raw_entry)
            metadata_keys = entry_keys & _TASK12_METADATA_KEYS
            if (
                not _BASE_ENTRY_KEYS <= entry_keys <= _ENTRY_KEYS
                or (metadata_keys and metadata_keys != _TASK12_METADATA_KEYS)
                or (
                    metadata_keys == _TASK12_METADATA_KEYS
                    and (
                        raw_entry.get("calibration_report_sha256") is None
                        or raw_entry.get("runtime_download") is None
                    )
                )
                or not isinstance(raw_entry.get("files"), list)
                or not 1 <= len(raw_entry["files"]) <= MAX_MODEL_FILES
            ):
                raise ValueError("invalid model manifest")
            raw_files = raw_entry["files"]
            if any(not isinstance(item, dict) or set(item) != _FILE_KEYS for item in raw_files):
                raise ValueError("invalid model manifest")
            try:
                files = tuple(ModelFile(**item) for item in raw_files)
                entry = ModelEntry(
                    model_id=raw_entry["id"],
                    files=files,
                    **{
                        key: raw_entry[key]
                        for key in _BASE_ENTRY_KEYS
                        if key not in {"id", "files"}
                    },
                    calibration_report_sha256=raw_entry.get("calibration_report_sha256"),
                    runtime_download=raw_entry.get("runtime_download"),
                )
            except (KeyError, TypeError, ValueError, OverflowError) as error:
                raise ValueError("invalid model manifest") from error
            if entry.model_id in entries:
                raise ValueError("invalid model manifest")
            entries[entry.model_id] = entry
        return cls(entries, model_root)

    @property
    def models(self) -> tuple[ModelEntry, ...]:
        return tuple(self._entries[key] for key in sorted(self._entries))

    def entry(self, model_id: str) -> ModelEntry:
        try:
            return self._entries[model_id]
        except KeyError as error:
            raise LookupError("model is not registered") from error

    def activate(self, model_id: str) -> ActivatedModel:
        """Return a caller-owned lease over the activated model descriptors."""
        entry = self.entry(model_id)
        activated_slot = _ActivatedModelOwnerSlot()
        root_slot = _OwnedDirectoryOwnerSlot()
        model_slot = _OwnedDirectoryOwnerSlot()
        lock_slot = _FileDescriptorOwnerSlot()
        try:
            OwnedDirectory.open(self._root, root_slot)
            root = root_slot.owner
            if root is None:
                raise RuntimeError("model root acquisition missing")
            with root.lock(
                model_install_lock_name(entry.model_id),
                lock_slot,
                timeout_seconds=30.0,
                shared=True,
            ):
                root.child(entry.model_id, model_slot)
                model = model_slot.owner
                if model is None:
                    raise RuntimeError("model directory acquisition missing")
                self._activate_from_open_model(model, entry, activated_slot)
                model.close()
            root.close()
            activated = activated_slot.owner
            if activated is None:
                raise RuntimeError("model is not installed and verified")
            return activated if setattr(activated_slot, "owner", None) is None else activated  # type: ignore[func-returns-value]
        except BaseException as error:
            if activated_slot.owner is not None:
                close_preserving_primary(activated_slot.owner, ActivatedModel.close, error)
            if model_slot.owner is not None:
                close_preserving_primary(model_slot.owner, OwnedDirectory.close, error)
            if lock_slot.owner is not None:
                close_preserving_primary(lock_slot.owner, _FileDescriptorOwner.close, error)
            if root_slot.owner is not None:
                close_preserving_primary(root_slot.owner, OwnedDirectory.close, error)
            if not isinstance(error, Exception):
                raise
            raise RuntimeError("model is not installed and verified") from error

    @staticmethod
    def _activate_from_open_model(
        model: OwnedDirectory,
        entry: ModelEntry,
        activated_slot: _ActivatedModelOwnerSlot,
    ) -> None:
        if activated_slot.owner is not None:
            raise ValueError("activated model owner slot already populated")
        handles: list[VerifiedModelFile] = []
        revision_slot = _OwnedDirectoryOwnerSlot()
        commit_slot = _FileDescriptorOwnerSlot()
        descriptor_slot = _FileDescriptorOwnerSlot()
        handle_slot = _VerifiedModelFileOwnerSlot()
        try:
            pending_name = recovery_pending_name(entry.revision)
            if entry_exists_at(model, pending_name):
                raise PermissionError("model revision recovery is pending")
            open_publication_commit(model, entry.revision, commit_slot)
            commit_owner = commit_slot.owner
            if commit_owner is None:
                raise RuntimeError("publication commit acquisition missing")
            model.child(entry.revision, revision_slot, mode=0o500)
            revision = revision_slot.owner
            if revision is None:
                raise RuntimeError("model revision acquisition missing")
            expected_names = tuple(sorted(item.path for item in entry.files))
            if tuple(sorted(os.listdir(revision.fd))) != expected_names:
                raise PermissionError("unsafe model filesystem revision")
            for item in entry.files:
                descriptor_slot = _FileDescriptorOwnerSlot()
                handle_slot = _VerifiedModelFileOwnerSlot()
                open_regular_at(
                    revision,
                    item.path,
                    os.O_RDONLY,
                    descriptor_slot,
                    mode=0o400,
                    expected_mode=0o400,
                )
                descriptor_owner = descriptor_slot.owner
                if descriptor_owner is None:
                    raise RuntimeError("model artifact descriptor acquisition missing")
                hash_exact_fd(descriptor_owner.fileno(), item.size, item.sha256)
                VerifiedModelFile.from_manifest(item, descriptor_slot, handle_slot)
                handle = handle_slot.owner
                if handle is None:
                    raise RuntimeError("verified model file acquisition missing")
                handles.append(handle)
                handle_slot.owner = None
            if tuple(sorted(os.listdir(revision.fd))) != expected_names:
                raise PermissionError("unsafe model filesystem revision")
            if entry_exists_at(model, pending_name):
                raise PermissionError("model revision recovery is pending")
            require_publication_commit(
                model,
                entry.revision,
                commit_owner.fileno(),
                expected_mode=0o400,
                require_read_only=True,
            )
            ActivatedModel.from_manifest(entry, tuple(handles), activated_slot)
            handles.clear()
            if (
                activated_slot.owner is None
                or revision_slot.owner is None
                or commit_slot.owner is None
            ):
                raise RuntimeError("model activation did not retain verified files")
            revision_slot.owner.close()
            commit_slot.owner.close()
        except BaseException as error:
            if activated_slot.owner is None:
                for handle in handles:
                    close_preserving_primary(handle, VerifiedModelFile.close, error)
            if handle_slot.owner is not None:
                close_preserving_primary(handle_slot.owner, VerifiedModelFile.close, error)
            if descriptor_slot.owner is not None:
                close_preserving_primary(
                    descriptor_slot.owner,
                    _FileDescriptorOwner.close,
                    error,
                )
            if revision_slot.owner is not None:
                close_preserving_primary(revision_slot.owner, OwnedDirectory.close, error)
            if commit_slot.owner is not None:
                close_preserving_primary(commit_slot.owner, _FileDescriptorOwner.close, error)
            raise
