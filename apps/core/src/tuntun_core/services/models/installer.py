from __future__ import annotations

import contextlib
import errno
import fcntl
import functools
import hashlib
import io
import os
import secrets
import stat
import time
from collections.abc import Callable, Iterator
from enum import Enum, auto
from typing import Any
from urllib.parse import urlsplit

from .fs import (
    AtomicPublishWitness,
    OwnedDirectory,
    atomic_publish_dir_noreplace,
    close_preserving_primary,
    entry_exists_at,
    hash_exact_fd,
    model_install_lock_name,
    open_regular_at,
    publication_commit_name,
    recovery_pending_name,
    require_publication_commit,
)
from .network import PinnedHttpsTransport
from .registry import (
    ActivatedModel,
    ModelEntry,
    ModelFile,
    ModelRegistry,
    VerifiedModelFile,
    _ActivatedModelOwnerSlot,
)

WriteOnce = Callable[[int, bytes | memoryview], int]
FaultHook = Callable[[str], None]
_RECOVERY_ROLLBACK_NOTE = "additional recovery rollback failure"
_PUBLICATION_RESOLUTION_NOTE = "additional publication commit resolution failure"


def _write_once(descriptor: int, data: bytes | memoryview) -> int:
    return os.write(descriptor, data)


def _no_fault(_point: str) -> None:
    return None


class _PublicationMarkerOwner(io.FileIO):
    """C-backed, idempotent ownership for the retained publication marker FD."""


class _PublicationMarkerOwnerSlot:
    """Transaction-visible marker ownership populated before acquisition returns."""

    __slots__ = ("owner",)

    def __init__(self) -> None:
        self.owner: _PublicationMarkerOwner | None = None


class _PublicationResolution(Enum):
    COMMITTED = auto()
    DEFINITELY_PRECOMMIT = auto()
    INCONCLUSIVE = auto()


@contextlib.contextmanager
def _close_owned_directory(directory: OwnedDirectory) -> Iterator[None]:
    """Close one directory without replacing an active body failure."""
    try:
        yield
    except BaseException as error:
        close_preserving_primary(directory, OwnedDirectory.close, error)
        raise
    else:
        directory.close()


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
        except BaseException as error:
            if read_fd is not None:
                descriptor_to_close = read_fd
                read_fd = None
                close_preserving_primary(descriptor_to_close, os.close, error)
            if write_fd >= 0:
                descriptor_to_close = write_fd
                write_fd = -1
                close_preserving_primary(descriptor_to_close, os.close, error)
            raise

    @staticmethod
    def _open_existing_revision(model: OwnedDirectory, revision: str) -> OwnedDirectory | None:
        try:
            return model.child(revision)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise PermissionError("unsafe model filesystem revision") from error

    @staticmethod
    def _require_recovery_marker_name_before_open(
        model: OwnedDirectory,
        revision: str,
        *,
        create: bool,
    ) -> None:
        name = recovery_pending_name(revision)
        try:
            identity = os.stat(name, dir_fd=model.fd, follow_symlinks=False)
        except FileNotFoundError:
            if create:
                return
            raise
        if create:
            raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), name)
        if (
            not stat.S_ISREG(identity.st_mode)
            or identity.st_uid != os.geteuid()
            or stat.S_IMODE(identity.st_mode) not in {0o400, 0o600}
            or identity.st_nlink != 1
            or identity.st_size != 0
        ):
            raise PermissionError("unsafe model recovery marker")

    @staticmethod
    def _acquire_recovery_marker(
        model: OwnedDirectory,
        revision: str,
        owner_slot: _PublicationMarkerOwnerSlot,
        *,
        create: bool,
    ) -> None:
        if owner_slot.owner is not None:
            raise ValueError("publication marker owner slot already populated")
        ModelInstaller._require_recovery_marker_name_before_open(
            model,
            revision,
            create=create,
        )
        owner_slot.owner = _PublicationMarkerOwner(
            recovery_pending_name(revision),
            "x+b" if create else "rb",
            opener=functools.partial(os.open, mode=0o600, dir_fd=model.fd),
        )
        descriptor = owner_slot.owner.fileno()
        observed_mode = stat.S_IMODE(os.fstat(descriptor).st_mode)
        allowed_modes = {0o600} if create else {0o400, 0o600}
        expected_access = os.O_RDWR if create else os.O_RDONLY
        if (
            observed_mode not in allowed_modes
            or fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE != expected_access
            or os.get_inheritable(descriptor)
        ):
            raise PermissionError("unsafe model recovery marker")
        ModelInstaller._require_recovery_marker(
            model,
            revision,
            descriptor,
            expected_mode=observed_mode,
        )
        os.fsync(descriptor)
        model.fsync()
        ModelInstaller._require_recovery_marker(
            model,
            revision,
            descriptor,
            expected_mode=observed_mode,
        )

    @staticmethod
    def _require_recovery_marker(
        model: OwnedDirectory,
        revision: str,
        descriptor: int,
        *,
        expected_mode: int,
    ) -> None:
        name = recovery_pending_name(revision)
        identity = os.fstat(descriptor)
        named = os.stat(name, dir_fd=model.fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(identity.st_mode)
            or identity.st_uid != os.geteuid()
            or stat.S_IMODE(identity.st_mode) != expected_mode
            or identity.st_nlink != 1
            or identity.st_size != 0
            or (identity.st_dev, identity.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise PermissionError("unsafe model recovery marker")

    @staticmethod
    def _prepare_recovery_marker_as_publication(
        model: OwnedDirectory,
        revision: str,
        descriptor: int,
    ) -> None:
        observed_mode = stat.S_IMODE(os.fstat(descriptor).st_mode)
        if observed_mode not in {0o400, 0o600}:
            raise PermissionError("unsafe model recovery marker")
        ModelInstaller._require_recovery_marker(
            model,
            revision,
            descriptor,
            expected_mode=observed_mode,
        )
        if observed_mode == 0o600:
            os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        model.fsync()
        ModelInstaller._require_recovery_marker(
            model,
            revision,
            descriptor,
            expected_mode=0o400,
        )

    @staticmethod
    def _publish_prepared_recovery_marker(
        model: OwnedDirectory,
        revision: str,
        descriptor: int,
        expected_identity: tuple[int, int],
        *,
        witness: AtomicPublishWitness,
    ) -> None:
        pending_name = recovery_pending_name(revision)
        commit_name = publication_commit_name(revision)
        publication_error: BaseException | None = None
        try:
            atomic_publish_dir_noreplace(
                model,
                pending_name,
                commit_name,
                expected_source_fd=descriptor,
                expected_source_identity=expected_identity,
                witness=witness,
            )
        except BaseException as error:
            if witness.committed:
                if isinstance(error, Exception):
                    return
                raise
            publication_error = error
        if not witness.committed:
            try:
                if entry_exists_at(model, pending_name):
                    raise PermissionError("model publication is still pending")
                require_publication_commit(
                    model,
                    revision,
                    descriptor,
                    expected_mode=0o400,
                    require_read_only=False,
                )
            except BaseException:
                if publication_error is not None:
                    raise publication_error from None
                raise RuntimeError("model publication outcome missing") from None
            witness.committed = True
        if publication_error is not None and not isinstance(publication_error, Exception):
            raise publication_error

    @staticmethod
    def _reresolve_publication_witness_after_exception(
        model: OwnedDirectory,
        revision: str,
        marker_owner: _PublicationMarkerOwner,
        witness: AtomicPublishWitness,
        primary_error: BaseException,
    ) -> _PublicationResolution:
        if witness.committed:
            return _PublicationResolution.COMMITTED
        descriptor = marker_owner.fileno()
        retained = os.fstat(descriptor)
        pending_name = recovery_pending_name(revision)
        try:
            named = os.stat(pending_name, dir_fd=model.fd, follow_symlinks=False)
        except FileNotFoundError:
            require_publication_commit(
                model,
                revision,
                descriptor,
                expected_mode=0o400,
                require_read_only=False,
            )
            resolution = _PublicationResolution.COMMITTED
        else:
            if (retained.st_dev, retained.st_ino) == (named.st_dev, named.st_ino):
                return _PublicationResolution.DEFINITELY_PRECOMMIT
            resolution = _PublicationResolution.INCONCLUSIVE
        if resolution is _PublicationResolution.COMMITTED:
            try:
                witness.committed = True
            except BaseException:
                primary_error.add_note(_PUBLICATION_RESOLUTION_NOTE)
        elif resolution is _PublicationResolution.INCONCLUSIVE:
            primary_error.add_note(_PUBLICATION_RESOLUTION_NOTE)
        return resolution

    @staticmethod
    def _remove_publication_commit(model: OwnedDirectory, revision: str) -> None:
        name = publication_commit_name(revision)
        try:
            descriptor = open_regular_at(
                model,
                name,
                os.O_RDONLY,
                expected_mode=None,
            )
        except FileNotFoundError:
            return
        try:
            identity = os.fstat(descriptor)
            named = os.stat(name, dir_fd=model.fd, follow_symlinks=False)
            if (
                stat.S_IMODE(identity.st_mode) not in {0o400, 0o600}
                or identity.st_size != 0
                or (identity.st_dev, identity.st_ino) != (named.st_dev, named.st_ino)
            ):
                raise PermissionError("unsafe model publication commit")
            os.unlink(name, dir_fd=model.fd)
            model.fsync()
        except BaseException as error:
            close_preserving_primary(descriptor, os.close, error)
            raise
        os.close(descriptor)

    def _reuse_or_recover_revision(
        self,
        model: OwnedDirectory,
        entry: ModelEntry,
        activated_slot: _ActivatedModelOwnerSlot,
    ) -> bool:
        if activated_slot.owner is not None:
            raise ValueError("activated model owner slot already populated")
        pending_name = recovery_pending_name(entry.revision)
        pending_exists = entry_exists_at(model, pending_name)
        commit_exists = entry_exists_at(model, publication_commit_name(entry.revision))
        revision = self._open_existing_revision(model, entry.revision)
        if revision is None:
            if pending_exists or commit_exists:
                raise PermissionError("unsafe model recovery marker")
            return False
        handles: list[VerifiedModelFile] = []
        marker_owner_slot = _PublicationMarkerOwnerSlot()
        sealed_for_recovery = False
        committed_on_entry = False
        post_seal_phase = False
        publication_witness = AtomicPublishWitness()
        try:
            mode = stat.S_IMODE(os.fstat(revision.fd).st_mode)
            sealed_for_recovery = mode == 0o500
            if mode == 0o500 and not pending_exists and commit_exists:
                committed_on_entry = True
                try:
                    self.registry._activate_from_open_model(model, entry, activated_slot)
                except BaseException as error:
                    if not isinstance(error, Exception):
                        raise
                    raise RuntimeError("model is not installed and verified") from error
            else:
                if mode not in {0o500, 0o700}:
                    raise PermissionError("unsafe model filesystem revision")

                if pending_exists:
                    self._acquire_recovery_marker(
                        model,
                        entry.revision,
                        marker_owner_slot,
                        create=False,
                    )

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
                    except BaseException as error:
                        close_preserving_primary(descriptor, os.close, error)
                        raise
                    try:
                        self._fault_hook("before_retain_recovery_file")
                        handles.append(handle)
                    except BaseException as error:
                        close_preserving_primary(handle, VerifiedModelFile.close, error)
                        raise

                if marker_owner_slot.owner is None:
                    self._acquire_recovery_marker(
                        model,
                        entry.revision,
                        marker_owner_slot,
                        create=True,
                    )
                marker_owner = marker_owner_slot.owner
                if marker_owner is None:
                    raise RuntimeError("model recovery marker acquisition missing")
                marker_fd = marker_owner.fileno()
                self._remove_publication_commit(model, entry.revision)
                if mode == 0o700:
                    revision.chmod(0o500)
                    sealed_for_recovery = True
                    revision.fsync()
                else:
                    sealed_for_recovery = True
                post_seal_phase = True
                self._fault_hook("after_recovery_seal_before_verify")
                if tuple(sorted(os.listdir(revision.fd))) != expected_names:
                    raise PermissionError("unsafe unsealed model revision")
                for item, handle in zip(entry.files, handles, strict=True):
                    hash_exact_fd(handle.fd, item.size, item.sha256)
                revision.fsync()
                model.fsync()
                self._prepare_recovery_marker_as_publication(
                    model,
                    entry.revision,
                    marker_fd,
                )
                prepared_marker = os.fstat(marker_fd)
                prepared_marker_identity = (
                    prepared_marker.st_dev,
                    prepared_marker.st_ino,
                )
                self._publish_prepared_recovery_marker(
                    model,
                    entry.revision,
                    marker_fd,
                    prepared_marker_identity,
                    witness=publication_witness,
                )
                self._fault_hook("before_publication_marker_close")
                marker_owner.close()
                self._fault_hook("after_publication_marker_close")
                activated_slot.owner = ActivatedModel.from_manifest(entry, tuple(handles))
                handles.clear()
        except BaseException as error:
            if sealed_for_recovery and not committed_on_entry and not publication_witness.committed:
                resolution = _PublicationResolution.INCONCLUSIVE
                if marker_owner_slot.owner is not None:
                    try:
                        resolution = self._reresolve_publication_witness_after_exception(
                            model,
                            entry.revision,
                            marker_owner_slot.owner,
                            publication_witness,
                            error,
                        )
                    except BaseException:
                        error.add_note(_PUBLICATION_RESOLUTION_NOTE)
                else:
                    error.add_note(_PUBLICATION_RESOLUTION_NOTE)
                if resolution is _PublicationResolution.DEFINITELY_PRECOMMIT:
                    try:
                        revision.chmod(0o700)
                        revision.fsync()
                    except BaseException:
                        error.add_note(_RECOVERY_ROLLBACK_NOTE)
            if activated_slot.owner is None:
                for handle in handles:
                    close_preserving_primary(handle, VerifiedModelFile.close, error)
            if marker_owner_slot.owner is not None:
                close_preserving_primary(
                    marker_owner_slot.owner,
                    _PublicationMarkerOwner.close,
                    error,
                )
            close_preserving_primary(revision, OwnedDirectory.close, error)
            if isinstance(error, OSError) and not post_seal_phase:
                raise PermissionError("unsafe unsealed model revision") from error
            raise
        if activated_slot.owner is None:
            revision.close()
            raise RuntimeError("model revision recovery did not activate")
        revision.close()
        return True

    def install(self, model_id: str) -> ActivatedModel:
        entry = self.registry.entry(model_id)
        activated_slot = _ActivatedModelOwnerSlot()
        resolve_publication = self._reresolve_publication_witness_after_exception
        try:
            root = OwnedDirectory.open_or_create(self.registry._root)
            with (
                _close_owned_directory(root),
                root.lock(
                    model_install_lock_name(entry.model_id),
                    timeout_seconds=30.0,
                ),
            ):
                model = root.child(entry.model_id, create=True, exist_ok=True)
                with _close_owned_directory(model):
                    prefix = f".stage-{entry.revision}-"
                    model.remove_private_stages(prefix)
                    model.fsync()
                    reused = self._reuse_or_recover_revision(
                        model,
                        entry,
                        activated_slot,
                    )
                    if not reused:
                        stage_name = f"{prefix}{secrets.token_hex(8)}"
                        stage = model.child(stage_name, create=True)
                        with _close_owned_directory(stage):
                            stage_identity = stage.identity
                            published = False
                            sealed_for_publication = False
                            publication_witness = AtomicPublishWitness()
                            handles: list[VerifiedModelFile] = []
                            marker_owner_slot = _PublicationMarkerOwnerSlot()
                            try:
                                deadline = time.monotonic() + self.MAX_TOTAL_DOWNLOAD_SECONDS
                                for item in entry.files:
                                    descriptor = self._download(stage, item, deadline)
                                    try:
                                        handle = VerifiedModelFile.from_manifest(
                                            item,
                                            descriptor,
                                        )
                                    except BaseException as error:
                                        close_preserving_primary(
                                            descriptor,
                                            os.close,
                                            error,
                                        )
                                        raise
                                    try:
                                        self._fault_hook("before_retain_downloaded_file")
                                        handles.append(handle)
                                    except BaseException as error:
                                        close_preserving_primary(
                                            handle,
                                            VerifiedModelFile.close,
                                            error,
                                        )
                                        raise
                                    self._fault_hook("after_each_file")
                                for item, handle in zip(
                                    entry.files,
                                    handles,
                                    strict=True,
                                ):
                                    hash_exact_fd(
                                        handle.fd,
                                        item.size,
                                        item.sha256,
                                    )
                                self._fault_hook("before_stage_fsync")
                                stage.fsync()
                                self._fault_hook("after_stage_fsync")
                                self._fault_hook("before_publish")
                                atomic_publish_dir_noreplace(
                                    model,
                                    stage_name,
                                    entry.revision,
                                )
                                published = True
                                self._fault_hook("after_publish_before_seal")
                                self._acquire_recovery_marker(
                                    model,
                                    entry.revision,
                                    marker_owner_slot,
                                    create=True,
                                )
                                marker_owner = marker_owner_slot.owner
                                if marker_owner is None:
                                    raise RuntimeError("model recovery marker acquisition missing")
                                marker_fd = marker_owner.fileno()
                                stage.chmod(0o500)
                                sealed_for_publication = True
                                stage.fsync()
                                self._fault_hook("after_publish_before_parent_fsync")
                                model.fsync()
                                expected_names = tuple(sorted(item.path for item in entry.files))
                                if tuple(sorted(os.listdir(stage.fd))) != expected_names:
                                    raise PermissionError("unsafe model filesystem revision")
                                for item, handle in zip(
                                    entry.files,
                                    handles,
                                    strict=True,
                                ):
                                    hash_exact_fd(
                                        handle.fd,
                                        item.size,
                                        item.sha256,
                                    )
                                self._prepare_recovery_marker_as_publication(
                                    model,
                                    entry.revision,
                                    marker_fd,
                                )
                                prepared_marker = os.fstat(marker_fd)
                                prepared_marker_identity = (
                                    prepared_marker.st_dev,
                                    prepared_marker.st_ino,
                                )
                                self._publish_prepared_recovery_marker(
                                    model,
                                    entry.revision,
                                    marker_fd,
                                    prepared_marker_identity,
                                    witness=publication_witness,
                                )
                                self._fault_hook("before_publication_marker_close")
                                marker_owner.close()
                                self._fault_hook("after_publication_marker_close")
                                activated_slot.owner = ActivatedModel.from_manifest(
                                    entry,
                                    tuple(handles),
                                )
                                handles.clear()
                            except FileExistsError as error:
                                if published:
                                    if sealed_for_publication and not publication_witness.committed:
                                        resolution = _PublicationResolution.INCONCLUSIVE
                                        if marker_owner_slot.owner is not None:
                                            try:
                                                resolution = resolve_publication(
                                                    model,
                                                    entry.revision,
                                                    marker_owner_slot.owner,
                                                    publication_witness,
                                                    error,
                                                )
                                            except BaseException:
                                                error.add_note(_PUBLICATION_RESOLUTION_NOTE)
                                        else:
                                            error.add_note(_PUBLICATION_RESOLUTION_NOTE)
                                        if (
                                            resolution
                                            is _PublicationResolution.DEFINITELY_PRECOMMIT
                                        ):
                                            try:
                                                stage.chmod(0o700)
                                                stage.fsync()
                                            except BaseException:
                                                error.add_note(_RECOVERY_ROLLBACK_NOTE)
                                    if activated_slot.owner is None:
                                        for handle in handles:
                                            close_preserving_primary(
                                                handle,
                                                VerifiedModelFile.close,
                                                error,
                                            )
                                    if marker_owner_slot.owner is not None:
                                        close_preserving_primary(
                                            marker_owner_slot.owner,
                                            _PublicationMarkerOwner.close,
                                            error,
                                        )
                                    raise
                                for handle in handles:
                                    with contextlib.suppress(OSError):
                                        handle.close()
                                model.remove_private_stage(
                                    stage_name,
                                    stage_identity,
                                )
                                model.fsync()
                                reused = self._reuse_or_recover_revision(
                                    model,
                                    entry,
                                    activated_slot,
                                )
                                if not reused:
                                    raise RuntimeError(
                                        "model install publication disappeared"
                                    ) from None
                            except BaseException as error:
                                if sealed_for_publication and not publication_witness.committed:
                                    resolution = _PublicationResolution.INCONCLUSIVE
                                    if marker_owner_slot.owner is not None:
                                        try:
                                            resolution = resolve_publication(
                                                model,
                                                entry.revision,
                                                marker_owner_slot.owner,
                                                publication_witness,
                                                error,
                                            )
                                        except BaseException:
                                            error.add_note(_PUBLICATION_RESOLUTION_NOTE)
                                    else:
                                        error.add_note(_PUBLICATION_RESOLUTION_NOTE)
                                    if resolution is _PublicationResolution.DEFINITELY_PRECOMMIT:
                                        try:
                                            stage.chmod(0o700)
                                            stage.fsync()
                                        except BaseException:
                                            error.add_note(_RECOVERY_ROLLBACK_NOTE)
                                if activated_slot.owner is None:
                                    for handle in handles:
                                        close_preserving_primary(
                                            handle,
                                            VerifiedModelFile.close,
                                            error,
                                        )
                                if marker_owner_slot.owner is not None:
                                    close_preserving_primary(
                                        marker_owner_slot.owner,
                                        _PublicationMarkerOwner.close,
                                        error,
                                    )
                                if not published:
                                    try:
                                        model.remove_private_stage(
                                            stage_name,
                                            stage_identity,
                                        )
                                        model.fsync()
                                    except FileNotFoundError:
                                        pass
                                raise
        except BaseException as error:
            if activated_slot.owner is not None:
                close_preserving_primary(
                    activated_slot.owner,
                    ActivatedModel.close,
                    error,
                )
            raise
        activated = activated_slot.owner
        if activated is None:
            raise RuntimeError("model install did not activate")
        activated_slot.owner = None
        return activated
