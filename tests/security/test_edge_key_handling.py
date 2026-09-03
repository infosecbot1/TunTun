from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

import pytest
from tuntun_edge.security.key_store import EdgeKeyStore


def test_key_store_uses_private_directory_and_file_modes(tmp_path: Path) -> None:
    store = EdgeKeyStore(tmp_path / "keys")

    store.write("device-signing", b"s" * 32)

    assert stat.S_IMODE(store.root.stat().st_mode) == 0o700
    assert stat.S_IMODE((store.root / "device-signing.key").stat().st_mode) == 0o600
    assert store.read("device-signing") == b"s" * 32


@pytest.mark.parametrize(
    "key_id",
    ("", ".", "..", "device/signing", "device_signing", "Device", "device\x00key"),
)
def test_key_ids_are_not_paths_or_public_identifiers(tmp_path: Path, key_id: str) -> None:
    store = EdgeKeyStore(tmp_path / "keys")

    with pytest.raises(ValueError, match="invalid edge key identifier"):
        store.write(key_id, b"k" * 32)


@pytest.mark.parametrize("value", (b"x" * 31, b"x" * 4097))
def test_key_bytes_are_bounded_without_leaking_material(tmp_path: Path, value: bytes) -> None:
    store = EdgeKeyStore(tmp_path / "keys")

    with pytest.raises(ValueError) as error:
        store.write("device-signing", value)

    assert value[:8].hex() not in str(error.value)
    assert value.decode("ascii", errors="ignore")[:8] not in repr(store)


def test_key_read_rejects_symlink_without_following(tmp_path: Path) -> None:
    store = EdgeKeyStore(tmp_path / "keys")
    target = tmp_path / "target.key"
    target.write_bytes(b"t" * 32)
    (store.root / "device-signing.key").symlink_to(target)

    with pytest.raises(PermissionError, match="edge_key_file_unsafe"):
        store.read("device-signing")


def test_key_read_rejects_hardlinked_key(tmp_path: Path) -> None:
    store = EdgeKeyStore(tmp_path / "keys")
    store.write("device-signing", b"s" * 32)
    os.link(store.root / "device-signing.key", store.root / "device-signing-copy.key")

    with pytest.raises(PermissionError, match="edge_key_file_unsafe"):
        store.read("device-signing")


def test_key_store_rejects_symlinked_root_without_resolving_to_target(tmp_path: Path) -> None:
    real_root = tmp_path / "real-keys"
    real_root.mkdir()
    symlink_root = tmp_path / "keys"
    symlink_root.symlink_to(real_root)

    with pytest.raises(PermissionError, match="edge_key_root_unsafe"):
        EdgeKeyStore(symlink_root)


def test_key_store_rejects_symlinked_ancestor(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    symlink_parent = tmp_path / "link-parent"
    symlink_parent.symlink_to(real_parent)

    with pytest.raises(PermissionError, match="edge_key_root_unsafe"):
        EdgeKeyStore(symlink_parent / "keys")


@pytest.mark.parametrize("root", (Path("."), Path(".."), Path("/"), Path("/tmp/tuntun\x00keys")))
def test_key_store_rejects_raw_dot_dotdot_and_broad_roots(root: Path) -> None:
    with pytest.raises(PermissionError, match="edge_key_root_unsafe"):
        EdgeKeyStore(root)


def test_key_read_rejects_named_inode_replacement_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EdgeKeyStore(tmp_path / "keys")
    store.write("device-signing", b"s" * 32)
    replacement = store.root / "replacement.key"
    replacement.write_bytes(b"r" * 32)
    replacement.chmod(0o600)
    real_stat = os.stat
    named_stats = 0

    def replace_name_on_second_stat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        nonlocal named_stats
        if (
            path == "device-signing.key"
            and kwargs.get("dir_fd") is not None
            and kwargs.get("follow_symlinks") is False
        ):
            named_stats += 1
            if named_stats == 2:
                replacement.replace(store.root / "device-signing.key")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", replace_name_on_second_stat)

    with pytest.raises(PermissionError, match="edge_key_identity_changed"):
        store.read("device-signing")

    assert named_stats >= 2


def test_failed_key_write_removes_unpublished_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EdgeKeyStore(tmp_path / "keys")
    real_write = os.write

    def short_write(fd: int, payload: bytes) -> int:
        if payload == b"k" * 32:
            return 0
        return real_write(fd, payload)

    monkeypatch.setattr(os, "write", short_write)

    with pytest.raises(OSError, match="edge_key_write_incomplete"):
        store.write("device-signing", b"k" * 32)

    assert not (store.root / "device-signing.key").exists()


def test_key_write_parent_fsync_failure_removes_uncommitted_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EdgeKeyStore(tmp_path / "keys")
    real_fsync = os.fsync
    directory_fsyncs = 0

    def fail_first_directory_fsync(fd: int) -> None:
        nonlocal directory_fsyncs
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_fsyncs += 1
            if directory_fsyncs == 1:
                raise OSError("directory fsync failed")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_first_directory_fsync)

    with pytest.raises(OSError, match="directory fsync failed"):
        store.write("device-signing", b"k" * 32)

    assert not (store.root / "device-signing.key").exists()
    assert directory_fsyncs >= 2


def test_key_reader_rejects_visible_key_while_publication_marker_exists(
    tmp_path: Path,
) -> None:
    store = EdgeKeyStore(tmp_path / "keys")
    key_path = store.root / "device-signing.key"
    key_path.write_bytes(b"k" * 32)
    key_path.chmod(0o600)
    marker = store.root / ".device-signing.key.publish"
    marker.write_bytes(b"publication pending")
    marker.chmod(0o600)

    with pytest.raises(PermissionError, match="edge_key_publication_uncommitted"):
        store.read("device-signing")

    marker.unlink()
    assert store.read("device-signing") == b"k" * 32


def test_key_write_post_publish_fsync_failure_retains_quarantine_marker_and_blocks_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EdgeKeyStore(tmp_path / "keys")
    real_fsync = os.fsync
    directory_fsyncs = 0

    def fail_second_directory_fsync(fd: int) -> None:
        nonlocal directory_fsyncs
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_fsyncs += 1
            if directory_fsyncs == 2:
                raise OSError("directory commit failed")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_second_directory_fsync)

    with pytest.raises(OSError, match="directory commit failed"):
        store.write("device-signing", b"k" * 32)

    assert directory_fsyncs >= 2
    assert (store.root / ".device-signing.key.publish").exists()
    with pytest.raises(PermissionError, match="edge_key_publication_uncommitted"):
        store.read("device-signing")


def test_key_write_final_marker_removal_fsync_failure_keeps_reader_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EdgeKeyStore(tmp_path / "keys")
    real_fsync = os.fsync
    directory_fsyncs = 0

    def fail_marker_removal_commit(fd: int) -> None:
        nonlocal directory_fsyncs
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_fsyncs += 1
            if directory_fsyncs == 4:
                raise OSError("final marker removal fsync failed")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_marker_removal_commit)

    with pytest.raises(PermissionError, match="edge_key_publication_uncommitted"):
        store.write("device-signing", b"k" * 32)

    assert directory_fsyncs >= 4
    assert (store.root / ".device-signing.key.publish").exists()
    with pytest.raises(PermissionError, match="edge_key_publication_uncommitted"):
        store.read("device-signing")


def test_key_write_final_marker_restore_failure_quarantines_visible_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EdgeKeyStore(tmp_path / "keys")
    real_fsync = os.fsync
    real_open = os.open
    directory_fsyncs = 0
    publish_marker_creates = 0

    def fail_marker_removal_commit(fd: int) -> None:
        nonlocal directory_fsyncs
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_fsyncs += 1
            if directory_fsyncs == 4:
                raise OSError("scripted directory durability failure")
        real_fsync(fd)

    def fail_publish_marker_restore(
        path: Any,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal publish_marker_creates
        if path == ".device-signing.key.publish" and flags & os.O_EXCL:
            publish_marker_creates += 1
            if publish_marker_creates == 2:
                raise PermissionError("scripted marker restoration failure")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "fsync", fail_marker_removal_commit)
    monkeypatch.setattr(os, "open", fail_publish_marker_restore)

    with pytest.raises(PermissionError, match="edge_key_publication_uncommitted"):
        store.write("device-signing", b"k" * 32)

    assert publish_marker_creates == 2
    assert (store.root / "device-signing.key").exists()
    assert (store.root / ".device-signing.key.publish.quarantine").exists()
    with pytest.raises(PermissionError, match="edge_key_publication_uncommitted"):
        EdgeKeyStore(store.root).read("device-signing")


def test_losing_key_writer_does_not_remove_concurrent_publication_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EdgeKeyStore(tmp_path / "keys")
    real_open = os.open
    marker_name = ".device-signing.key.publish"

    def concurrent_marker_owner(
        path: Any,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == marker_name and flags & os.O_EXCL:
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            try:
                os.write(descriptor, b"winner owns publication marker")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            raise FileExistsError("winner owns marker")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", concurrent_marker_owner)

    with pytest.raises(FileExistsError, match="winner owns marker"):
        store.write("device-signing", b"k" * 32)

    marker = store.root / marker_name
    assert marker.exists()
    with pytest.raises(PermissionError, match="edge_key_publication_uncommitted"):
        store.read("device-signing")


def test_failed_existing_key_write_does_not_delete_committed_key(tmp_path: Path) -> None:
    store = EdgeKeyStore(tmp_path / "keys")
    store.write("device-signing", b"s" * 32)

    with pytest.raises(OSError):
        store.write("device-signing", b"k" * 32)

    assert store.read("device-signing") == b"s" * 32


@pytest.mark.parametrize("drift", ("mode", "link", "same_size_content"))
def test_key_read_revalidates_same_inode_metadata_after_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    store = EdgeKeyStore(tmp_path / "keys")
    store.write("device-signing", b"s" * 32)
    key_path = store.root / "device-signing.key"
    real_stat = os.stat
    named_stats = 0

    def drift_before_final_named_stat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        nonlocal named_stats
        if (
            path == "device-signing.key"
            and kwargs.get("dir_fd") is not None
            and kwargs.get("follow_symlinks") is False
        ):
            named_stats += 1
            if named_stats == 2:
                if drift == "mode":
                    key_path.chmod(0o644)
                elif drift == "link":
                    hardlink = store.root / "device-signing-hardlink.key"
                    if not hardlink.exists():
                        os.link(key_path, hardlink)
                else:
                    key_path.write_bytes(b"r" * 32)
                    os.utime(key_path, ns=(1_900_000_000_000_000_000, 1_900_000_000_000_000_000))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", drift_before_final_named_stat)

    with pytest.raises(PermissionError, match="edge_key_(identity_changed|file_unsafe)"):
        store.read("device-signing")

    assert named_stats >= 2


def test_delete_revalidates_named_key_identity_before_unlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EdgeKeyStore(tmp_path / "keys")
    store.write("device-signing", b"s" * 32)
    replacement = store.root / "replacement.key"
    replacement.write_bytes(b"r" * 32)
    replacement.chmod(0o600)
    real_stat = os.stat
    named_stats = 0

    def replace_before_final_delete_stat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        nonlocal named_stats
        if (
            path == "device-signing.key"
            and kwargs.get("dir_fd") is not None
            and kwargs.get("follow_symlinks") is False
        ):
            named_stats += 1
            if named_stats == 2:
                replacement.replace(store.root / "device-signing.key")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", replace_before_final_delete_stat)

    with pytest.raises(PermissionError, match="edge_key_identity_changed"):
        store.delete("device-signing")

    assert (store.root / "device-signing.key").exists()
