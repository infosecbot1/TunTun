from __future__ import annotations

import contextlib
import fcntl
import hashlib
import os
import secrets
import stat
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from .fs import (
    OwnedDirectory,
    atomic_publish_dir_noreplace,
    hash_exact_fd,
    open_regular_at,
)
from .network import PinnedHttpsTransport
from .registry import ActivatedModel, ModelEntry, ModelFile, ModelRegistry, VerifiedModelFile

WriteOnce = Callable[[int, bytes | memoryview], int]
FaultHook = Callable[[str], None]


def _write_once(descriptor: int, data: bytes | memoryview) -> int:
    return os.write(descriptor, data)


def _no_fault(_point: str) -> None:
    return None


class ModelInstaller:
    MAX_TOTAL_DOWNLOAD_SECONDS = 900.0

    def __init__(
        self,
        registry: ModelRegistry,
        allowed_hosts: frozenset[str] | set[str],
        transport: Any | None = None,
        *,
        write_once: WriteOnce | None = None,
        fault_hook: FaultHook | None = None,
    ) -> None:
        self.registry = registry
        self.allowed_hosts = frozenset(allowed_hosts)
        self.transport = transport or PinnedHttpsTransport()
        self._write_once = write_once or _write_once
        self._fault_hook = fault_hook or _no_fault

    def _download(self, stage: OwnedDirectory, item: ModelFile, deadline: float) -> int:
        try:
            hostname = urlsplit(item.url).hostname
        except ValueError as error:
            raise PermissionError("model URL is not allowlisted HTTPS") from error
        if hostname not in self.allowed_hosts:
            raise PermissionError("model URL is not allowlisted HTTPS")
        write_fd = open_regular_at(
            stage,
            item.path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            mode=0o600,
            expected_mode=0o600,
        )
        read_fd: int | None = None
        try:
            read_fd = open_regular_at(
                stage, item.path, os.O_RDONLY, mode=0o600, expected_mode=0o600
            )
            written_identity = os.fstat(write_fd)
            read_identity = os.fstat(read_fd)
            if (
                not stat.S_ISREG(written_identity.st_mode)
                or written_identity.st_uid != os.geteuid()
                or written_identity.st_nlink != 1
                or (written_identity.st_dev, written_identity.st_ino)
                != (read_identity.st_dev, read_identity.st_ino)
                or fcntl.fcntl(read_fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
            ):
                raise PermissionError("model staged descriptor identity invalid")
            digest = hashlib.sha256()
            total = 0
            with self.transport.stream_exact(item.url, self.allowed_hosts, deadline) as response:
                if response.status != 200:
                    raise PermissionError("model redirect or response rejected")
                length = response.headers.get("content-length")
                encoding = response.headers.get("content-encoding")
                if encoding not in {None, "identity"}:
                    raise ValueError("model response encoding rejected")
                if length is not None and (
                    not isinstance(length, str)
                    or not length.isascii()
                    or not length.isdecimal()
                    or int(length) != item.size
                ):
                    raise ValueError("model size/hash mismatch")
                while True:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("model download total deadline")
                    chunk = response.read(65_536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > item.size:
                        raise ValueError("model size/hash mismatch")
                    view = memoryview(chunk)
                    while view:
                        written = self._write_once(write_fd, view)
                        if written <= 0:
                            raise OSError("model artifact write made no progress")
                        view = view[written:]
                    digest.update(chunk)
            if total != item.size or digest.hexdigest() != item.sha256:
                raise ValueError("model size/hash mismatch")
            os.fchmod(write_fd, 0o400)
            os.fsync(write_fd)
            final_write = os.fstat(write_fd)
            final_read = os.fstat(read_fd)
            if (
                not stat.S_ISREG(final_write.st_mode)
                or not stat.S_ISREG(final_read.st_mode)
                or final_write.st_uid != os.geteuid()
                or final_read.st_uid != os.geteuid()
                or stat.S_IMODE(final_read.st_mode) != 0o400
                or final_write.st_size != item.size
                or final_read.st_size != item.size
                or final_write.st_nlink != 1
                or final_read.st_nlink != 1
                or (final_write.st_dev, final_write.st_ino)
                != (written_identity.st_dev, written_identity.st_ino)
                or (final_read.st_dev, final_read.st_ino)
                != (written_identity.st_dev, written_identity.st_ino)
            ):
                raise ValueError("model size/hash mismatch")
            hash_exact_fd(read_fd, item.size, item.sha256)
            descriptor_to_close = write_fd
            write_fd = -1
            os.close(descriptor_to_close)
            return read_fd
        except BaseException:
            if read_fd is not None:
                descriptor_to_close = read_fd
                read_fd = None
                with contextlib.suppress(OSError):
                    os.close(descriptor_to_close)
            if write_fd >= 0:
                descriptor_to_close = write_fd
                write_fd = -1
                with contextlib.suppress(OSError):
                    os.close(descriptor_to_close)
            raise

    @staticmethod
    def _open_existing_revision(model: OwnedDirectory, revision: str) -> OwnedDirectory | None:
        try:
            return model.child(revision)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise PermissionError("unsafe model filesystem revision") from error

    def _reuse_or_recover_revision(
        self,
        model: OwnedDirectory,
        entry: ModelEntry,
    ) -> ActivatedModel | None:
        revision = self._open_existing_revision(model, entry.revision)
        if revision is None:
            return None
        handles: list[VerifiedModelFile] = []
        activated: ActivatedModel | None = None
        sealed_by_recovery = False
        post_seal_verified = False
        try:
            mode = stat.S_IMODE(os.fstat(revision.fd).st_mode)
            if mode == 0o500:
                activated = self.registry.activate(entry.model_id)
            else:
                if mode != 0o700:
                    raise PermissionError("unsafe model filesystem revision")

                expected_names = tuple(sorted(item.path for item in entry.files))
                if tuple(sorted(os.listdir(revision.fd))) != expected_names:
                    raise PermissionError("unsafe unsealed model revision")
                for item in entry.files:
                    descriptor = open_regular_at(
                        revision,
                        item.path,
                        os.O_RDONLY,
                        mode=0o400,
                        expected_mode=0o400,
                    )
                    try:
                        hash_exact_fd(descriptor, item.size, item.sha256)
                        handle = VerifiedModelFile.from_manifest(item, descriptor)
                    except BaseException:
                        with contextlib.suppress(OSError):
                            os.close(descriptor)
                        raise
                    try:
                        handles.append(handle)
                    except BaseException:
                        handle.close()
                        raise

                sealed_by_recovery = True
                revision.chmod(0o500)
                revision.fsync()
                self._fault_hook("after_recovery_seal_before_verify")
                if tuple(sorted(os.listdir(revision.fd))) != expected_names:
                    raise PermissionError("unsafe unsealed model revision")
                for item, handle in zip(entry.files, handles, strict=True):
                    hash_exact_fd(handle.fd, item.size, item.sha256)
                post_seal_verified = True
                model.fsync()
                activated = ActivatedModel.from_manifest(entry, tuple(handles))
                handles.clear()
        except BaseException as error:
            rollback_error: BaseException | None = None
            if sealed_by_recovery and not post_seal_verified:
                try:
                    revision.chmod(0o700)
                    revision.fsync()
                except BaseException as caught:
                    rollback_error = caught
            for handle in handles:
                with contextlib.suppress(OSError):
                    handle.close()
            with contextlib.suppress(OSError):
                revision.close()
            if rollback_error is not None:
                raise PermissionError("unsafe unsealed model revision") from rollback_error
            if isinstance(error, OSError):
                raise PermissionError("unsafe unsealed model revision") from error
            raise
        if activated is None:
            revision.close()
            raise RuntimeError("model revision recovery did not activate")
        try:
            revision.close()
        except BaseException:
            activated.close()
            raise
        return activated

    def install(self, model_id: str) -> ActivatedModel:
        entry = self.registry.entry(model_id)
        root = OwnedDirectory.open_or_create(self.registry._root)
        try:
            with root.lock(".model-install.lock", timeout_seconds=30.0):
                model = root.child(entry.model_id, create=True, exist_ok=True)
                try:
                    prefix = f".stage-{entry.revision}-"
                    model.remove_private_stages(prefix)
                    model.fsync()
                    existing = self._reuse_or_recover_revision(model, entry)
                    if existing is not None:
                        return existing
                    stage_name = f"{prefix}{secrets.token_hex(8)}"
                    stage = model.child(stage_name, create=True)
                    stage_identity = stage.identity
                    published = False
                    handles: list[VerifiedModelFile] = []
                    try:
                        deadline = time.monotonic() + self.MAX_TOTAL_DOWNLOAD_SECONDS
                        for item in entry.files:
                            descriptor = self._download(stage, item, deadline)
                            try:
                                handle = VerifiedModelFile.from_manifest(item, descriptor)
                            except BaseException:
                                os.close(descriptor)
                                raise
                            try:
                                handles.append(handle)
                            except BaseException:
                                handle.close()
                                raise
                            self._fault_hook("after_each_file")
                        for item, handle in zip(entry.files, handles, strict=True):
                            hash_exact_fd(handle.fd, item.size, item.sha256)
                        self._fault_hook("before_stage_fsync")
                        stage.fsync()
                        self._fault_hook("after_stage_fsync")
                        self._fault_hook("before_publish")
                        atomic_publish_dir_noreplace(model, stage_name, entry.revision)
                        published = True
                        self._fault_hook("after_publish_before_seal")
                        stage.chmod(0o500)
                        stage.fsync()
                        self._fault_hook("after_publish_before_parent_fsync")
                        model.fsync()
                        return ActivatedModel.from_manifest(entry, tuple(handles))
                    except FileExistsError:
                        for handle in handles:
                            with contextlib.suppress(OSError):
                                handle.close()
                        if not published:
                            model.remove_private_stage(stage_name, stage_identity)
                            model.fsync()
                        existing = self._reuse_or_recover_revision(model, entry)
                        if existing is None:
                            raise RuntimeError("model install publication disappeared") from None
                        return existing
                    except BaseException:
                        for handle in handles:
                            with contextlib.suppress(OSError):
                                handle.close()
                        if not published:
                            try:
                                model.remove_private_stage(stage_name, stage_identity)
                                model.fsync()
                            except FileNotFoundError:
                                pass
                        raise
                    finally:
                        stage.close()
                finally:
                    model.close()
        finally:
            root.close()
