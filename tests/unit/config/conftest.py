from __future__ import annotations

import errno
import os
import stat
import struct
import subprocess
import sys
from collections.abc import Callable, Iterator
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import pytest

LINUX_POSIX_ACL_ACCESS = b"system.posix_acl_access"
LINUX_POSIX_ACL_DEFAULT = b"system.posix_acl_default"
AclKind = Literal["access", "inherit", "deny"]


@dataclass
class DescriptorAudit:
    _real_close: Callable[[int], None]
    active: dict[int, str]
    opened: list[str]
    closed: list[str]
    repeated: list[int]
    fail_label: str | None = None
    _failure_raised: bool = False

    @classmethod
    def create(cls) -> DescriptorAudit:
        return cls(os.close, {}, [], [], [])

    def acquire(self, descriptor: int, label: str) -> int:
        assert descriptor not in self.active
        token = f"{len(self.opened)}:{label}"
        self.active[descriptor] = token
        self.opened.append(token)
        return descriptor

    def close(self, descriptor: int) -> None:
        token = self.active.pop(descriptor, None)
        if token is None:
            self.repeated.append(descriptor)
            raise AssertionError("descriptor close was attempted more than once")
        self.closed.append(token)
        self._real_close(descriptor)
        if self.fail_label is not None and self.fail_label in token and not self._failure_raised:
            self._failure_raised = True
            raise OSError("sensitive ambiguous descriptor close failure")

    def assert_all_closed_once(self) -> None:
        assert self.active == {}
        assert self.repeated == []
        assert sorted(self.closed) == sorted(self.opened)

    def cleanup(self) -> None:
        for descriptor in tuple(self.active):
            with suppress(OSError):
                self._real_close(descriptor)
            self.active.pop(descriptor, None)


@pytest.fixture
def descriptor_audit() -> Iterator[DescriptorAudit]:
    audit = DescriptorAudit.create()
    yield audit
    audit.cleanup()


@dataclass
class NativeUnsafeAclLease:
    original_raw: bytes | None
    installed_raw: bytes | None
    original_mode: int
    installed_mode: int
    _snapshot: Callable[[], bytes | None]
    _snapshot_mode: Callable[[], int]
    _restore: Callable[[], None]

    def assert_installed_unchanged(self) -> None:
        assert self._snapshot() == self.installed_raw
        assert self._snapshot_mode() == self.installed_mode == self.original_mode

    def restore_original(self) -> None:
        self._restore()
        assert self._snapshot() == self.original_raw
        assert self._snapshot_mode() == self.original_mode


UnsafeAclInstaller = Callable[[Path, AclKind], NativeUnsafeAclLease]


def _darwin_acl_lease(path: Path, kind: AclKind) -> NativeUnsafeAclLease:
    def snapshot() -> bytes:
        raw = subprocess.run(
            ["/bin/ls", "-lde", str(path)],
            check=True,
            capture_output=True,
        ).stdout
        return b"".join(raw.splitlines(keepends=True)[1:])

    original = snapshot()

    def snapshot_mode() -> int:
        return stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)

    original_mode = snapshot_mode()
    acl = {
        "access": "everyone allow read",
        "inherit": (
            "everyone allow add_file,add_subdirectory,delete_child,file_inherit,directory_inherit"
        ),
        "deny": "everyone deny delete",
    }[kind]
    completed = subprocess.run(
        ["/bin/chmod", "+a#", "0", acl, str(path)],
        check=False,
        capture_output=True,
    )
    assert completed.returncode == 0, "filesystem cannot establish a Darwin extended ACL"

    def restore() -> None:
        subprocess.run(
            ["/bin/chmod", "-a#", "0", str(path)],
            check=True,
            capture_output=True,
        )

    lease = NativeUnsafeAclLease(
        original,
        snapshot(),
        original_mode,
        snapshot_mode(),
        snapshot,
        snapshot_mode,
        restore,
    )
    if lease.installed_raw == original:
        lease.restore_original()
        pytest.fail("filesystem did not retain a Darwin extended ACL")
    return lease


def _linux_acl_lease(path: Path, kind: AclKind) -> NativeUnsafeAclLease:
    getter = getattr(os, "getxattr", None)
    setter = getattr(os, "setxattr", None)
    remover = getattr(os, "removexattr", None)
    if not callable(getter) or not callable(setter) or not callable(remover):
        pytest.fail("platform has no extended-attribute API")
    missing_errnos = {errno.ENODATA, getattr(errno, "ENOATTR", errno.ENODATA)}
    attribute = LINUX_POSIX_ACL_DEFAULT if kind == "inherit" else LINUX_POSIX_ACL_ACCESS

    def snapshot_attribute(target_attribute: bytes) -> bytes | None:
        try:
            return getter(path, target_attribute)
        except OSError as error:
            if error.errno in missing_errnos:
                return None
            raise

    def snapshot() -> bytes | None:
        return snapshot_attribute(attribute)

    original = snapshot()
    original_access = snapshot_attribute(LINUX_POSIX_ACL_ACCESS)

    def snapshot_mode() -> int:
        return stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)

    original_mode = snapshot_mode()
    owner_permissions = original_mode >> 6 & 0o7
    group_permissions = original_mode >> 3 & 0o7
    other_permissions = original_mode & 0o7
    payload = struct.pack("<I", 2) + b"".join(
        struct.pack("<HHI", tag, permissions, identifier)
        for tag, permissions, identifier in (
            (0x01, owner_permissions, 0xFFFFFFFF),
            (0x02, 0, os.geteuid() + 1),
            (0x04, group_permissions, 0xFFFFFFFF),
            (0x10, group_permissions, 0xFFFFFFFF),
            (0x20, other_permissions, 0xFFFFFFFF),
        )
    )
    setter(path, attribute, payload)

    def restore() -> None:
        if original is None:
            try:
                remover(path, attribute)
            except OSError as error:
                if error.errno not in missing_errnos:
                    raise
        else:
            setter(path, attribute, original)
        if snapshot_mode() != original_mode:
            path.chmod(original_mode)
            if original_access is not None:
                setter(path, LINUX_POSIX_ACL_ACCESS, original_access)

    lease = NativeUnsafeAclLease(
        original,
        snapshot(),
        original_mode,
        snapshot_mode(),
        snapshot,
        snapshot_mode,
        restore,
    )
    if lease.installed_raw is None or lease.installed_raw == original:
        lease.restore_original()
        pytest.fail("filesystem did not retain a Linux POSIX ACL")
    if lease.installed_mode != original_mode:
        lease.restore_original()
        pytest.fail("installing a Linux POSIX ACL changed the existing mode")
    return lease


@pytest.fixture
def native_unsafe_acl_installer() -> Iterator[UnsafeAclInstaller]:
    leases: list[NativeUnsafeAclLease] = []

    def install(path: Path, kind: AclKind) -> NativeUnsafeAclLease:
        if sys.platform == "darwin":
            lease = _darwin_acl_lease(path, kind)
        elif sys.platform.startswith("linux"):
            lease = _linux_acl_lease(path, kind)
        else:
            pytest.fail("native ACL regression requires Darwin or Linux")
        leases.append(lease)
        return lease

    yield install
    for lease in reversed(leases):
        lease.restore_original()


def _write_private(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


@dataclass
class StrictSettingsCase:
    path: Path
    monkeypatch: pytest.MonkeyPatch

    def mutate(self, mutation: str) -> None:
        if mutation == "duplicate_key":
            _write_private(
                self.path,
                "memory:\n  max_items_per_turn: 5\nmemory: {}\n",
            )
        elif mutation == "yaml_alias":
            _write_private(
                self.path,
                "memory: &m {max_items_per_turn: 5}\ncopy: *m\n",
            )
        elif mutation == "explicit_tag":
            _write_private(
                self.path,
                "memory: !custom {max_items_per_turn: 5}\n",
            )
        elif mutation == "overdeep":
            _write_private(
                self.path,
                "unknown: " + "[" * 33 + "0" + "]" * 33 + "\n",
            )
        elif mutation == "too_many_events":
            _write_private(
                self.path,
                "unknown: [" + ",".join("0" for _ in range(16_385)) + "]\n",
            )
        elif mutation == "oversized_file":
            self.path.write_bytes(b"#" * 262_145)
            self.path.chmod(0o600)
        elif mutation == "invalid_utf8":
            self.path.write_bytes(b"\xff")
            self.path.chmod(0o600)
        elif mutation == "multiple_documents":
            _write_private(self.path, "---\n{}\n---\n{}\n")
        elif mutation == "symlink":
            target = self.path.with_name("target.yaml")
            _write_private(target, "{}\n")
            self.path.unlink()
            self.path.symlink_to(target.name)
        elif mutation == "hardlink":
            target = self.path.with_name("target.yaml")
            _write_private(target, "{}\n")
            self.path.unlink()
            os.link(target, self.path)
        elif mutation == "ancestor_symlink":
            real_parent = self.path.parent / "real-parent"
            real_parent.mkdir(mode=0o700)
            target = real_parent / "settings.yaml"
            _write_private(target, "memory:\n  max_items_per_turn: 5\n")
            alias = self.path.parent / "alias-parent"
            alias.symlink_to(real_parent, target_is_directory=True)
            self.path = alias / "settings.yaml"
        elif mutation == "fifo":
            self.path.unlink()
            os.mkfifo(self.path, 0o600)
        elif mutation == "group_writable":
            self.path.chmod(0o620)
        elif mutation == "group_readable":
            self.path.chmod(0o640)
        elif mutation == "world_readable":
            self.path.chmod(0o604)
        elif mutation == "wrong_owner":
            from tuntun_core.config import loader

            self.monkeypatch.setattr(
                loader,
                "_reported_file_owner",
                lambda value: os.geteuid() + 1,
            )
        elif mutation == "same_inode_content_change":
            from tuntun_core.config import loader

            original_read = loader.os.read
            changed = False

            def rewriting_read(fd: int, size: int) -> bytes:
                nonlocal changed
                chunk = original_read(fd, size)
                if chunk and not changed:
                    changed = True
                    _write_private(
                        self.path,
                        "memory:\n  max_items_per_turn: 4\n",
                    )
                return chunk

            self.monkeypatch.setattr(loader.os, "read", rewriting_read)
        elif mutation == "changed_during_read":
            from tuntun_core.config import loader

            replacement = self.path.with_name("replacement.yaml")
            _write_private(replacement, "memory:\n  max_items_per_turn: 4\n")
            original_read = loader.os.read
            swapped = False

            def replacing_read(fd: int, size: int) -> bytes:
                nonlocal swapped
                chunk = original_read(fd, size)
                if chunk and not swapped:
                    swapped = True
                    self.path.replace(self.path.with_name("original.yaml"))
                    replacement.replace(self.path)
                return chunk

            self.monkeypatch.setattr(loader.os, "read", replacing_read)
        elif mutation == "parent_changed_during_read":
            from tuntun_core.config import loader

            parent = self.path.parent / "settings-parent"
            parent.mkdir(mode=0o700)
            target = parent / "settings.yaml"
            _write_private(target, "memory:\n  max_items_per_turn: 5\n")
            self.path = target
            original_read = loader.os.read
            swapped = False

            def replacing_parent_read(fd: int, size: int) -> bytes:
                nonlocal swapped
                chunk = original_read(fd, size)
                if chunk and not swapped:
                    swapped = True
                    parent.rename(parent.with_name("opened-parent"))
                    parent.mkdir(mode=0o700)
                    _write_private(
                        parent / "settings.yaml",
                        "memory:\n  max_items_per_turn: 4\n",
                    )
                return chunk

            self.monkeypatch.setattr(loader.os, "read", replacing_parent_read)
        else:
            raise AssertionError(f"unknown strict-settings mutation: {mutation}")


@pytest.fixture
def strict_settings_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> StrictSettingsCase:
    path = tmp_path / "settings.yaml"
    _write_private(path, "memory:\n  max_items_per_turn: 5\n")
    return StrictSettingsCase(path, monkeypatch)
