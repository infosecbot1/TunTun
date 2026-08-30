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
from typing import Protocol
from urllib.parse import urlsplit

from .fs import (
    OwnedDirectory,
    close_preserving_primary,
    entry_exists_at,
    hash_exact_fd,
    open_regular_at,
    publication_is_uncertain,
    read_bounded_strict_yaml,
    recovery_pending_name,
)

SAFE_SUFFIXES = {".json", ".onnx", ".safetensors", ".tflite", ".txt"}
MODEL_ID = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
REVISION = re.compile(r"^[0-9a-f]{40,64}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
FILE_PATH = re.compile(r"^[A-Za-z0-9_.-]+\.(?:onnx|json|txt|tflite|safetensors)$")
MODEL_URL = re.compile(r"^https://[^/?#:@]+(?::443)?(?:/[^?#]*)$")
MAX_MODEL_FILE_BYTES = 4_000_000_000
MAX_MODEL_REVISION_BYTES = 8_000_000_000
MAX_MODEL_FILES = 64
MAX_MODELS = 256
_ENTRY_KEYS = frozenset(
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
_FILE_KEYS = frozenset({"path", "size", "sha256", "url"})


class ModelVerificationError(PermissionError):
    pass


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
        if (
            any(not isinstance(value, str) for value in scalar_values)
            or MODEL_ID.fullmatch(self.model_id) is None
            or REVISION.fullmatch(self.revision) is None
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


class PreadOnlyModelReader:
    __slots__ = (
        "__closed",
        "__digest",
        "__expected_sha256",
        "__fd",
        "__next_offset",
        "size",
    )

    def __init__(self, descriptor: int, size: int, expected_sha256: str) -> None:
        self.__fd = descriptor
        self.size = size
        self.__closed = False
        self.__next_offset = 0
        self.__digest = hashlib.sha256()
        self.__expected_sha256 = expected_sha256

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
        chunk = os.pread(self.__fd, min(length, self.size - offset), offset)
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
            self.__closed = True
            os.close(self.__fd)


@dataclass(frozen=True, slots=True)
class _ManifestBoundFile:
    path: str
    size: int
    sha256: str
    device: int
    inode: int


@dataclass(frozen=True)
class VerifiedModelFile:
    __descriptor: list[int]
    __expected: _ManifestBoundFile
    __lock: threading.Lock = field(default_factory=threading.Lock, compare=False, repr=False)

    @classmethod
    def from_manifest(cls, item: ModelFile, descriptor: int) -> VerifiedModelFile:
        metadata = os.fstat(descriptor)
        return cls(
            [descriptor],
            _ManifestBoundFile(item.path, item.size, item.sha256, metadata.st_dev, metadata.st_ino),
        )

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
            descriptor = self.__descriptor[0]
            if descriptor < 0:
                raise ModelVerificationError("verified model file is closed")
            return descriptor

    def _duplicate(self) -> int:
        with self.__lock:
            descriptor = self.__descriptor[0]
            if descriptor < 0:
                raise ModelVerificationError("verified model file is closed")
            return os.dup(descriptor)

    def verified(self) -> bool:
        duplicate = -1
        try:
            duplicate = self._duplicate()
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
            if duplicate >= 0:
                os.close(duplicate)
        return True

    def load_with(self, adapter: RuntimeAdapter) -> RuntimeFileReceipt:
        duplicate = self._duplicate()
        reader: PreadOnlyModelReader | None = None
        try:
            duplicate_metadata = os.fstat(duplicate)
            if fcntl.fcntl(duplicate, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY or (
                duplicate_metadata.st_dev,
                duplicate_metadata.st_ino,
            ) != (self.__expected.device, self.__expected.inode):
                raise ModelVerificationError("runtime model descriptor mismatch")
            hash_exact_fd(duplicate, self.__expected.size, self.__expected.sha256)
            reader = PreadOnlyModelReader(duplicate, self.__expected.size, self.__expected.sha256)
            duplicate = -1
            receipt = adapter.load_verified_reader(
                reader,
                self.__expected.path,
                self.__expected.size,
                self.__expected.sha256,
            )
            reader.require_complete()
            return receipt
        finally:
            if duplicate >= 0:
                os.close(duplicate)
            if reader is not None:
                reader.close()

    def close(self) -> None:
        with self.__lock:
            descriptor = self.__descriptor[0]
            self.__descriptor[0] = -1
        if descriptor >= 0:
            os.close(descriptor)


@dataclass(frozen=True)
class ActivatedModel:
    model_id: str
    revision: str
    __files: tuple[VerifiedModelFile, ...]
    __manifest_files: tuple[tuple[str, int, str], ...]
    __closed: list[bool] = field(default_factory=lambda: [False], compare=False, repr=False)
    __lock: threading.RLock = field(default_factory=threading.RLock, compare=False, repr=False)

    @classmethod
    def from_manifest(
        cls, entry: ModelEntry, files: tuple[VerifiedModelFile, ...]
    ) -> ActivatedModel:
        expected = tuple((item.path, item.size, item.sha256) for item in entry.files)
        observed = tuple((item.path, item.size, item.sha256) for item in files)
        if not files or observed != expected:
            raise ModelVerificationError("activated model is not manifest-bound")
        return cls(entry.model_id, entry.revision, files, expected)

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
            self.__closed[0] = True
            for item in self.__files:
                with contextlib.suppress(OSError):
                    item.close()


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
            if (
                not isinstance(raw_entry, dict)
                or set(raw_entry) != _ENTRY_KEYS
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
                    **{key: raw_entry[key] for key in _ENTRY_KEYS if key not in {"id", "files"}},
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
        entry = self.entry(model_id)
        handles: list[VerifiedModelFile] = []
        directories: list[OwnedDirectory] = []
        try:
            root = OwnedDirectory.open(self._root)
            directories.append(root)
            model = root.child(entry.model_id)
            directories.append(model)
            if publication_is_uncertain(model, entry.revision):
                raise PermissionError("model revision commit is uncertain")
            pending_name = recovery_pending_name(entry.revision)
            if entry_exists_at(model, pending_name):
                raise PermissionError("model revision recovery is pending")
            revision = model.child(entry.revision, mode=0o500)
            directories.append(revision)
            expected_names = tuple(sorted(item.path for item in entry.files))
            if tuple(sorted(os.listdir(revision.fd))) != expected_names:
                raise PermissionError("unsafe model filesystem revision")
            for item in entry.files:
                descriptor = open_regular_at(
                    revision, item.path, os.O_RDONLY, mode=0o400, expected_mode=0o400
                )
                try:
                    hash_exact_fd(descriptor, item.size, item.sha256)
                    handles.append(VerifiedModelFile.from_manifest(item, descriptor))
                except BaseException as error:
                    close_preserving_primary(descriptor, os.close, error)
                    raise
            if tuple(sorted(os.listdir(revision.fd))) != expected_names:
                raise PermissionError("unsafe model filesystem revision")
            if entry_exists_at(model, pending_name):
                raise PermissionError("model revision recovery is pending")
            if publication_is_uncertain(model, entry.revision):
                raise PermissionError("model revision commit is uncertain")
            return ActivatedModel.from_manifest(entry, tuple(handles))
        except BaseException as error:
            for handle in handles:
                close_preserving_primary(handle, VerifiedModelFile.close, error)
            raise RuntimeError("model is not installed and verified") from error
        finally:
            for directory in reversed(directories):
                directory.close()
