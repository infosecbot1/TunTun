from __future__ import annotations

import ctypes
import errno
import os
import stat
import sys
from pathlib import Path

import pytest
from tuntun_core.config import secure_paths
from tuntun_core.config.paths import ApplicationPaths
from tuntun_core.config.secure_paths import (
    ensure_private_directory,
    open_owned_directory,
)

DESCRIPTOR_CLEANUP_NOTE = "additional descriptor cleanup failure"


def _fixture_root(tmp_path: Path) -> Path:
    # pytest owns this root. Darwin may report it through a trusted temporary-
    # directory alias; production code never resolves an untrusted path.
    return Path(os.path.realpath(tmp_path))


def _audit_directory_descriptors(monkeypatch: pytest.MonkeyPatch, audit) -> None:
    original_root = secure_paths._open_root
    original_open = secure_paths._open_directory_at

    def recording_root() -> int:
        return audit.acquire(original_root(), "root")

    def recording_open(name: str, parent_fd: int) -> int:
        descriptor = original_open(name, parent_fd)
        metadata = os.fstat(descriptor)
        return audit.acquire(
            descriptor,
            f"component:{name}:{metadata.st_dev}:{metadata.st_ino}",
        )

    monkeypatch.setattr(secure_paths, "_open_root", recording_root)
    monkeypatch.setattr(secure_paths, "_open_directory_at", recording_open)
    monkeypatch.setattr(secure_paths, "_close_fd", audit.close)


def test_paths_are_absolute_and_created_owner_only(tmp_path: Path) -> None:
    base = _fixture_root(tmp_path) / "Tuntun"
    paths = ApplicationPaths.create(base)

    assert (
        paths.root,
        paths.data,
        paths.logs,
        paths.models,
        paths.backups,
    ) == (
        base,
        base / "data",
        base / "logs",
        base / "models",
        base / "backups",
    )

    for path in (
        paths.root,
        paths.data,
        paths.logs,
        paths.models,
        paths.backups,
    ):
        assert path.is_absolute()
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
    paths.revalidate()


def test_relative_base_returns_absolute_bound_identities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fixture_root(tmp_path)
    monkeypatch.chdir(root)
    paths = ApplicationPaths.create(Path("relative") / "Tuntun")
    monkeypatch.chdir(root.parent)

    assert paths.root == root / "relative" / "Tuntun"
    paths.revalidate()


@pytest.mark.parametrize("mode", (0o750, 0o755))
def test_nonwritable_readable_user_ancestor_is_accepted(
    tmp_path: Path,
    mode: int,
) -> None:
    root = _fixture_root(tmp_path)
    parent = root / "readable-parent"
    parent.mkdir(mode=0o700)
    parent.chmod(mode)

    identity = ensure_private_directory(parent / "private")

    assert stat.S_IMODE(identity.path.stat().st_mode) == 0o700
    identity.revalidate()


def test_root_sticky_ancestor_policy_is_explicit() -> None:
    assert secure_paths._ancestor_mode_is_safe(0, stat.S_IFDIR | 0o1777)
    assert not secure_paths._ancestor_mode_is_safe(
        0,
        stat.S_IFDIR | 0o0777,
    )


def test_linux_acl_policy_matches_the_task6_allowlist() -> None:
    for magic in (0xEF53, 0x58465342, 0x9123683E, 0x01021994, 0x794C7630, 0xF2F52010):
        secure_paths._require_supported_linux_acl_filesystem_magic(magic)
    for magic in (0x6969, 0xFF534D42, 0x2FC12FC1, 0xDEADBEEF):
        with pytest.raises(ValueError, match="unsupported Linux filesystem ACL semantics"):
            secure_paths._require_supported_linux_acl_filesystem_magic(magic)

    for attribute in (b"system.posix_acl_access", b"system.posix_acl_default"):
        assert secure_paths._classify_linux_acl_attribute(attribute) == "posix"
    assert secure_paths._classify_linux_acl_attribute(b"security.selinux") == "other"
    for attribute in (
        b"system.nfs4_acl",
        b"system.cifs_acl",
        b"system.richacl",
        b"security.NTACL",
        b"trusted.SGI_ACL_FILE",
    ):
        with pytest.raises(ValueError, match="unsupported Linux discretionary ACL"):
            secure_paths._classify_linux_acl_attribute(attribute)


def test_linux_acl_inventory_is_bounded_and_fails_closed_when_unsupported() -> None:
    class OversizedLister:
        argtypes: object = None
        restype: object = None

        def __call__(self, descriptor: int, names: object, size: int) -> int:
            del descriptor, names, size
            return 65_537

    class UnsupportedLister:
        argtypes: object = None
        restype: object = None

        def __call__(self, descriptor: int, names: object, size: int) -> int:
            del descriptor, names, size
            ctypes.set_errno(errno.EOPNOTSUPP)
            return -1

    for lister, message in (
        (OversizedLister(), "inventory is too large"),
        (UnsupportedLister(), "ACL inspection failed"),
    ):
        library = type("FakeLibrary", (), {"flistxattr": lister})()
        with pytest.raises(ValueError, match=message):
            secure_paths._linux_extended_attribute_names(library, 42)


def test_darwin_acl_inspection_uses_acl_type_extended() -> None:
    acl_types: list[int] = []

    class NoAclGetter:
        argtypes: object = None
        restype: object = None

        def __call__(self, descriptor: int, acl_type: int) -> None:
            del descriptor
            acl_types.append(acl_type)
            ctypes.set_errno(errno.ENOENT)
            return None

    class UnusedNativeFunction:
        argtypes: object = None
        restype: object = None

        def __call__(self, *args: object) -> int:
            del args
            raise AssertionError("no-entry ACL must not inspect entries")

    library = type(
        "FakeLibrary",
        (),
        {
            "acl_get_fd_np": NoAclGetter(),
            "acl_get_entry": UnusedNativeFunction(),
            "acl_get_tag_type": UnusedNativeFunction(),
            "acl_free": UnusedNativeFunction(),
        },
    )()

    assert secure_paths._darwin_descriptor_has_unsafe_acl(library, 42) is False
    assert acl_types == [0x00000100]


def test_darwin_acl_inspection_allows_deny_only_and_rejects_allow_or_unknown() -> None:
    class Getter:
        argtypes: object = None
        restype: object = None

        def __init__(self) -> None:
            self.acl_types: list[int] = []

        def __call__(self, descriptor: int, acl_type: int) -> int:
            del descriptor
            self.acl_types.append(acl_type)
            return 99

    class EntryIterator:
        argtypes: object = None
        restype: object = None

        def __init__(self, tags: tuple[int, ...]) -> None:
            self.tags = tags
            self.index = 0

        def __call__(self, acl: object, entry_id: int, entry_pointer: object) -> int:
            del acl
            self.index = 0 if entry_id == 0 else self.index + 1
            if self.index >= len(self.tags):
                ctypes.set_errno(errno.EINVAL)
                return -1
            pointer = ctypes.cast(entry_pointer, ctypes.POINTER(ctypes.c_void_p))
            pointer[0] = ctypes.c_void_p(self.index + 1)
            return 0

    class TagGetter:
        argtypes: object = None
        restype: object = None

        def __init__(self, tags: tuple[int, ...]) -> None:
            self.tags = tags

        def __call__(self, entry: ctypes.c_void_p, tag_pointer: object) -> int:
            assert entry.value is not None
            pointer = ctypes.cast(tag_pointer, ctypes.POINTER(ctypes.c_int))
            pointer[0] = self.tags[entry.value - 1]
            return 0

    class Freer:
        argtypes: object = None
        restype: object = None

        def __init__(self) -> None:
            self.calls = 0

        def __call__(self, acl: object) -> int:
            del acl
            self.calls += 1
            return 0

    def inspect(tags: tuple[int, ...]) -> bool:
        getter = Getter()
        freer = Freer()
        library = type(
            "FakeLibrary",
            (),
            {
                "acl_get_fd_np": getter,
                "acl_get_entry": EntryIterator(tags),
                "acl_get_tag_type": TagGetter(tags),
                "acl_free": freer,
            },
        )()
        try:
            return secure_paths._darwin_descriptor_has_unsafe_acl(library, 42)
        finally:
            assert getter.acl_types == [0x00000100]
            assert freer.calls == 1

    assert inspect((2, 2)) is False
    assert inspect((2, 1)) is True
    with pytest.raises(ValueError, match="unsupported Darwin ACL entry type"):
        inspect((3,))
    with pytest.raises(ValueError, match="inventory is too large"):
        inspect((2,) * 129)


def test_darwin_acl_inspection_preserves_iterator_error_when_release_also_fails() -> None:
    class Getter:
        argtypes: object = None
        restype: object = None

        def __call__(self, descriptor: int, acl_type: int) -> int:
            del descriptor, acl_type
            return 99

    class FailingIterator:
        argtypes: object = None
        restype: object = None

        def __call__(self, acl: object, entry_id: int, entry_pointer: object) -> int:
            del acl, entry_id, entry_pointer
            ctypes.set_errno(errno.EIO)
            return -1

    class UnusedTagGetter:
        argtypes: object = None
        restype: object = None

        def __call__(self, entry: object, tag_pointer: object) -> int:
            del entry, tag_pointer
            raise AssertionError("iterator failure must remain primary")

    class FailingFreer:
        argtypes: object = None
        restype: object = None

        def __init__(self) -> None:
            self.calls = 0

        def __call__(self, acl: object) -> int:
            del acl
            self.calls += 1
            raise RuntimeError("sensitive ACL release exception")

    freer = FailingFreer()
    library = type(
        "FakeLibrary",
        (),
        {
            "acl_get_fd_np": Getter(),
            "acl_get_entry": FailingIterator(),
            "acl_get_tag_type": UnusedTagGetter(),
            "acl_free": freer,
        },
    )()

    with pytest.raises(ValueError, match="ACL entry inspection failed") as primary:
        secure_paths._darwin_descriptor_has_unsafe_acl(library, 42)

    assert freer.calls == 1
    assert primary.value.__notes__ == ["additional ACL release failure"]


@pytest.mark.parametrize("failure", ("tag", "free"))
def test_darwin_acl_tag_and_release_errors_fail_closed(failure: str) -> None:
    class Getter:
        argtypes: object = None
        restype: object = None

        def __call__(self, descriptor: int, acl_type: int) -> int:
            del descriptor, acl_type
            return 99

    class EntryIterator:
        argtypes: object = None
        restype: object = None

        def __init__(self) -> None:
            self.calls = 0

        def __call__(self, acl: object, entry_id: int, entry_pointer: object) -> int:
            del acl, entry_id
            self.calls += 1
            if self.calls == 1:
                pointer = ctypes.cast(entry_pointer, ctypes.POINTER(ctypes.c_void_p))
                pointer[0] = ctypes.c_void_p(1)
                return 0
            ctypes.set_errno(errno.EINVAL)
            return -1

    class TagGetter:
        argtypes: object = None
        restype: object = None

        def __call__(self, entry: object, tag_pointer: object) -> int:
            del entry
            if failure == "tag":
                ctypes.set_errno(errno.EIO)
                return -1
            pointer = ctypes.cast(tag_pointer, ctypes.POINTER(ctypes.c_int))
            pointer[0] = secure_paths.DARWIN_ACL_EXTENDED_DENY
            return 0

    class Freer:
        argtypes: object = None
        restype: object = None

        def __call__(self, acl: object) -> int:
            del acl
            if failure == "free":
                ctypes.set_errno(errno.EIO)
                return -1
            return 0

    library = type(
        "FakeLibrary",
        (),
        {
            "acl_get_fd_np": Getter(),
            "acl_get_entry": EntryIterator(),
            "acl_get_tag_type": TagGetter(),
            "acl_free": Freer(),
        },
    )()

    expected = "ACL tag inspection failed" if failure == "tag" else "ACL release failed"
    with pytest.raises(ValueError, match=expected):
        secure_paths._darwin_descriptor_has_unsafe_acl(library, 42)


def test_native_platform_acl_policy_case_is_deterministic_and_preserves_raw_state(
    tmp_path: Path,
    native_unsafe_acl_installer,
) -> None:
    ancestor = _fixture_root(tmp_path) / "policy-ancestor"
    descendant = ancestor / "private"
    descendant.mkdir(mode=0o700, parents=True)
    lease = native_unsafe_acl_installer(ancestor, "deny")

    if sys.platform == "darwin":
        with open_owned_directory(descendant) as opened:
            opened.revalidate()
        lease.assert_installed_unchanged()
        granting_lease = native_unsafe_acl_installer(ancestor, "access")
        with pytest.raises(PermissionError, match="unsafe application path"):
            open_owned_directory(descendant)
        granting_lease.assert_installed_unchanged()
    else:
        with pytest.raises(PermissionError, match="unsafe application path"):
            open_owned_directory(descendant)
        lease.assert_installed_unchanged()


@pytest.mark.parametrize(
    "mutation",
    (
        "ancestor_symlink",
        "root_symlink",
        "data_symlink",
        "data_fifo",
        "root_wrong_mode",
        "data_wrong_mode",
        "wrong_owner",
        "writable_ancestor",
    ),
)
def test_application_paths_reject_unsafe_existing_components(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    root = _fixture_root(tmp_path)
    base = root / "Tuntun"
    target = root / "target"
    target.mkdir(mode=0o700)

    if mutation == "ancestor_symlink":
        real = root / "real-parent"
        real.mkdir(mode=0o700)
        alias = root / "alias-parent"
        alias.symlink_to(real, target_is_directory=True)
        base = alias / "Tuntun"
    elif mutation == "root_symlink":
        base.symlink_to(target, target_is_directory=True)
    elif mutation == "writable_ancestor":
        parent = root / "writable-parent"
        parent.mkdir(mode=0o700)
        parent.chmod(0o770)
        base = parent / "Tuntun"
    else:
        base.mkdir(mode=0o700)
        if mutation == "data_symlink":
            (base / "data").symlink_to(target, target_is_directory=True)
        elif mutation == "data_fifo":
            os.mkfifo(base / "data", 0o600)
        elif mutation == "root_wrong_mode":
            base.chmod(0o750)
        elif mutation == "data_wrong_mode":
            (base / "data").mkdir(mode=0o700)
            (base / "data").chmod(0o750)
        elif mutation == "wrong_owner":
            monkeypatch.setattr(
                secure_paths,
                "_reported_owner",
                lambda value: os.geteuid() + 1,
            )

    with pytest.raises(PermissionError, match="unsafe application path"):
        ApplicationPaths.create(base)


def test_live_directory_guard_rejects_parent_replacement_and_closes_fd(
    tmp_path: Path,
) -> None:
    root = _fixture_root(tmp_path)
    base = root / "Tuntun"
    base.mkdir(mode=0o700)
    directory = open_owned_directory(base)
    held_fd = directory.fd
    base.rename(root / "opened-original")
    base.mkdir(mode=0o700)

    with pytest.raises(PermissionError, match="unsafe application path"):
        directory.revalidate()

    directory.close()
    with pytest.raises(OSError):
        os.fstat(held_fd)


def test_owned_path_fresh_walk_rejects_one_way_ancestor_replacement(
    tmp_path: Path,
) -> None:
    root = _fixture_root(tmp_path)
    parent = root / "parent"
    leaf = parent / "leaf"
    parent.mkdir(mode=0o700)
    identity = ensure_private_directory(leaf)
    parent.rename(root / "old-parent")
    parent.mkdir(mode=0o700)
    (parent / "leaf").mkdir(mode=0o700)

    with pytest.raises(PermissionError, match="unsafe application path"):
        identity.revalidate()


def test_open_then_named_component_swap_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fixture_root(tmp_path)
    base = root / "Tuntun"
    data = base / "data"
    data.mkdir(mode=0o700, parents=True)
    original_stat = secure_paths._stat_directory_at
    swapped = False

    def replacing_stat(name: str, parent_fd: int) -> os.stat_result:
        nonlocal swapped
        if name == "data" and not swapped:
            swapped = True
            data.rename(base / "opened-data")
            data.mkdir(mode=0o700)
        return original_stat(name, parent_fd)

    monkeypatch.setattr(
        secure_paths,
        "_stat_directory_at",
        replacing_stat,
    )

    with pytest.raises(PermissionError, match="unsafe application path"):
        open_owned_directory(data)


def test_walk_closes_every_opened_component_on_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fixture_root(tmp_path)
    target = root / "private"
    target.mkdir(mode=0o700)
    opened: list[int] = []
    original_root = secure_paths._open_root
    original_open = secure_paths._open_directory_at
    original_stat = secure_paths._stat_directory_at

    def recording_root() -> int:
        fd = original_root()
        opened.append(fd)
        return fd

    def recording_open(name: str, parent_fd: int) -> int:
        fd = original_open(name, parent_fd)
        opened.append(fd)
        return fd

    def failing_stat(name: str, parent_fd: int) -> os.stat_result:
        if name == "private":
            raise OSError("injected stat failure")
        return original_stat(name, parent_fd)

    monkeypatch.setattr(
        secure_paths,
        "_open_root",
        recording_root,
    )
    monkeypatch.setattr(
        secure_paths,
        "_open_directory_at",
        recording_open,
    )
    monkeypatch.setattr(
        secure_paths,
        "_stat_directory_at",
        failing_stat,
    )

    with pytest.raises(PermissionError, match="unsafe application path"):
        open_owned_directory(target)

    assert opened
    for fd in set(opened):
        with pytest.raises(OSError):
            os.fstat(fd)


def test_walk_transition_close_failure_does_not_retry_or_lose_child_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    descriptor_audit,
) -> None:
    target = _fixture_root(tmp_path) / "private"
    target.mkdir(mode=0o700)
    descriptor_audit.fail_label = "root"
    _audit_directory_descriptors(monkeypatch, descriptor_audit)

    with pytest.raises(PermissionError) as rejected:
        open_owned_directory(target)

    assert rejected.value.args == ("unsafe application path",)
    assert rejected.value.__cause__ is None
    assert rejected.value.__suppress_context__ is True
    assert "sensitive" not in str(rejected.value)
    descriptor_audit.assert_all_closed_once()


def test_root_owner_construction_failure_closes_raw_descriptor_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    descriptor_audit,
) -> None:
    target = _fixture_root(tmp_path) / "private"
    target.mkdir(mode=0o700)
    descriptor_audit.fail_label = "root"
    original_owner = secure_paths._OwnedDescriptor

    def reject_root_owner(descriptor: int):
        if descriptor_audit.active[descriptor].endswith(":root"):
            raise RuntimeError("primary root owner construction failure")
        return original_owner(descriptor)

    _audit_directory_descriptors(monkeypatch, descriptor_audit)
    monkeypatch.setattr(secure_paths, "_OwnedDescriptor", reject_root_owner)

    with pytest.raises(RuntimeError, match="primary root owner construction failure") as primary:
        open_owned_directory(target)

    assert primary.value.__notes__ == [DESCRIPTOR_CLEANUP_NOTE]
    descriptor_audit.assert_all_closed_once()


def test_existing_child_owner_construction_failure_closes_raw_descriptor_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    descriptor_audit,
) -> None:
    target_name = "constructor-existing-child"
    target = _fixture_root(tmp_path) / target_name
    target.mkdir(mode=0o700)
    target_label = f"component:{target_name}:"
    descriptor_audit.fail_label = target_label
    original_owner = secure_paths._OwnedDescriptor

    def reject_target_owner(descriptor: int):
        if target_label in descriptor_audit.active[descriptor]:
            raise RuntimeError("primary existing-child owner construction failure")
        return original_owner(descriptor)

    _audit_directory_descriptors(monkeypatch, descriptor_audit)
    monkeypatch.setattr(secure_paths, "_OwnedDescriptor", reject_target_owner)

    with pytest.raises(
        RuntimeError,
        match="primary existing-child owner construction failure",
    ) as primary:
        open_owned_directory(target)

    assert primary.value.__notes__ == [DESCRIPTOR_CLEANUP_NOTE]
    descriptor_audit.assert_all_closed_once()


def test_created_child_owner_construction_failure_closes_raw_descriptor_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    descriptor_audit,
) -> None:
    parent = _fixture_root(tmp_path) / "constructor-parent"
    parent.mkdir(mode=0o700)
    target_name = "constructor-created-child"
    target = parent / target_name
    target_label = f"component:{target_name}:"
    descriptor_audit.fail_label = target_label
    original_owner = secure_paths._OwnedDescriptor

    def reject_target_owner(descriptor: int):
        if target_label in descriptor_audit.active[descriptor]:
            raise RuntimeError("primary created-child owner construction failure")
        return original_owner(descriptor)

    _audit_directory_descriptors(monkeypatch, descriptor_audit)
    monkeypatch.setattr(secure_paths, "_OwnedDescriptor", reject_target_owner)

    with pytest.raises(
        RuntimeError,
        match="primary created-child owner construction failure",
    ) as primary:
        ensure_private_directory(target)

    assert primary.value.__notes__ == [DESCRIPTOR_CLEANUP_NOTE]
    descriptor_audit.assert_all_closed_once()


def test_walk_validation_preserves_primary_when_child_cleanup_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    descriptor_audit,
) -> None:
    target = _fixture_root(tmp_path) / "private"
    target.mkdir(mode=0o700)
    target_metadata = target.stat(follow_symlinks=False)
    target_identity = (target_metadata.st_dev, target_metadata.st_ino)
    descriptor_audit.fail_label = f":{target_identity[0]}:{target_identity[1]}"
    original_require = secure_paths._require_directory

    def fail_target_validation(
        descriptor: int,
        opened: os.stat_result,
        named: os.stat_result,
        *,
        leaf_private: bool,
    ) -> None:
        if (opened.st_dev, opened.st_ino) == target_identity:
            raise RuntimeError("primary directory validation failure")
        original_require(
            descriptor,
            opened,
            named,
            leaf_private=leaf_private,
        )

    _audit_directory_descriptors(monkeypatch, descriptor_audit)
    monkeypatch.setattr(secure_paths, "_require_directory", fail_target_validation)

    with pytest.raises(RuntimeError, match="primary directory validation failure") as primary:
        open_owned_directory(target)

    assert primary.value.__notes__ == [DESCRIPTOR_CLEANUP_NOTE]
    assert "sensitive" not in primary.value.__notes__[0]
    descriptor_audit.assert_all_closed_once()


def test_walk_result_construction_failure_retains_leaf_cleanup_ownership(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    descriptor_audit,
) -> None:
    target = _fixture_root(tmp_path) / "private"
    target.mkdir(mode=0o700)
    _audit_directory_descriptors(monkeypatch, descriptor_audit)

    def fail_construction(*args: object, **kwargs: object):
        del args, kwargs
        raise RuntimeError("primary directory result construction failure")

    monkeypatch.setattr(secure_paths, "OwnedDirectory", fail_construction)

    with pytest.raises(RuntimeError, match="primary directory result construction failure"):
        open_owned_directory(target)

    descriptor_audit.assert_all_closed_once()


def test_owned_directory_exit_preserves_body_error_and_invalidates_before_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    descriptor_audit,
) -> None:
    target = _fixture_root(tmp_path) / "private"
    target.mkdir(mode=0o700)
    opened = open_owned_directory(target)
    descriptor_audit.acquire(opened.fd, "owned-directory")
    descriptor_audit.fail_label = "owned-directory"
    monkeypatch.setattr(secure_paths, "_close_fd", descriptor_audit.close)

    with pytest.raises(RuntimeError, match="primary body failure") as primary, opened:
        raise RuntimeError("primary body failure")

    opened.close()
    assert primary.value.__notes__ == [DESCRIPTOR_CLEANUP_NOTE]
    assert "sensitive" not in primary.value.__notes__[0]
    descriptor_audit.assert_all_closed_once()


@pytest.mark.parametrize("release", ("close", "context"))
def test_owned_directory_cleanup_failure_without_body_is_fixed_and_one_shot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    descriptor_audit,
    release: str,
) -> None:
    target = _fixture_root(tmp_path) / "private"
    target.mkdir(mode=0o700)
    opened = open_owned_directory(target)
    descriptor_audit.acquire(opened.fd, "owned-directory")
    descriptor_audit.fail_label = "owned-directory"
    monkeypatch.setattr(secure_paths, "_close_fd", descriptor_audit.close)

    with pytest.raises(PermissionError) as rejected:
        if release == "close":
            opened.close()
        else:
            with opened:
                pass

    opened.close()
    assert rejected.value.args == ("unsafe application path",)
    assert rejected.value.__cause__ is None
    assert rejected.value.__suppress_context__ is True
    descriptor_audit.assert_all_closed_once()


def test_every_walked_directory_rejects_an_injected_unsafe_acl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fixture_root(tmp_path)
    parent = root / "acl-parent"
    target = parent / "private"
    parent.mkdir(mode=0o700)
    target.mkdir(mode=0o700)
    components = [Path("/")]
    for part in target.parts[1:]:
        components.append(components[-1] / part)
    identities = [
        (component.stat(follow_symlinks=False).st_dev, component.stat().st_ino)
        for component in components
    ]

    def acl_detector(
        expected: tuple[int, int],
        inspected: list[tuple[int, int]],
    ):
        def has_unsafe_acl(descriptor: int) -> bool:
            metadata = os.fstat(descriptor)
            identity = (metadata.st_dev, metadata.st_ino)
            inspected.append(identity)
            return identity == expected

        return has_unsafe_acl

    for unsafe_identity in identities:
        inspected: list[tuple[int, int]] = []

        monkeypatch.setattr(
            secure_paths,
            "_descriptor_has_unsafe_acl",
            acl_detector(unsafe_identity, inspected),
            raising=False,
        )
        with pytest.raises(PermissionError) as rejected:
            open_owned_directory(target)

        assert rejected.value.args == ("unsafe application path",)
        assert unsafe_identity in inspected


@pytest.mark.parametrize(
    "inspection_error",
    (
        ctypes.ArgumentError("sensitive ctypes diagnostic"),
        TypeError("sensitive type diagnostic"),
        RuntimeError("sensitive runtime diagnostic"),
    ),
)
def test_directory_unsafe_acl_inspection_failure_is_content_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    inspection_error: Exception,
) -> None:
    target = _fixture_root(tmp_path) / "private"
    target.mkdir(mode=0o700)

    def fail_inspection(descriptor: int) -> bool:
        del descriptor
        raise inspection_error

    monkeypatch.setattr(
        secure_paths,
        "_descriptor_has_unsafe_acl",
        fail_inspection,
        raising=False,
    )
    with pytest.raises(PermissionError) as rejected:
        open_owned_directory(target)

    assert rejected.value.args == ("unsafe application path",)
    assert "sensitive" not in str(rejected.value)
    assert rejected.value.__cause__ is None
    assert rejected.value.__suppress_context__ is True


def test_unsafe_creation_parent_acl_rejects_before_missing_child_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = _fixture_root(tmp_path) / "creation-parent"
    parent.mkdir(mode=0o700)
    child = parent / "missing"
    metadata = parent.stat(follow_symlinks=False)
    parent_identity = (metadata.st_dev, metadata.st_ino)
    before = (parent_identity, stat.S_IMODE(metadata.st_mode), tuple(parent.iterdir()))

    def has_unsafe_acl(descriptor: int) -> bool:
        opened = os.fstat(descriptor)
        return (opened.st_dev, opened.st_ino) == parent_identity

    monkeypatch.setattr(
        secure_paths,
        "_descriptor_has_unsafe_acl",
        has_unsafe_acl,
        raising=False,
    )
    with pytest.raises(PermissionError, match="unsafe application path"):
        ensure_private_directory(child)

    after_metadata = parent.stat(follow_symlinks=False)
    assert not child.exists()
    assert (
        (after_metadata.st_dev, after_metadata.st_ino),
        stat.S_IMODE(after_metadata.st_mode),
        tuple(parent.iterdir()),
    ) == before


def test_native_granting_directory_acl_is_rejected_without_mutating_raw_acl(
    tmp_path: Path,
    native_unsafe_acl_installer,
) -> None:
    target = _fixture_root(tmp_path) / "private"
    target.mkdir(mode=0o700)
    lease = native_unsafe_acl_installer(target, "access")

    with pytest.raises(PermissionError, match="unsafe application path"):
        open_owned_directory(target)

    lease.assert_installed_unchanged()


def test_native_inheritable_or_default_acl_rejects_creation_without_mutation(
    tmp_path: Path,
    native_unsafe_acl_installer,
) -> None:
    parent = _fixture_root(tmp_path) / "creation-parent"
    parent.mkdir(mode=0o700)
    child = parent / "missing"
    lease = native_unsafe_acl_installer(parent, "inherit")

    with pytest.raises(PermissionError, match="unsafe application path"):
        ensure_private_directory(child)

    assert not child.exists()
    assert tuple(parent.iterdir()) == ()
    lease.assert_installed_unchanged()


@pytest.mark.parametrize(
    "path",
    (
        Path("/"),
        Path("."),
        Path(".."),
        Path("safe/../escape"),
        Path("//double-root"),
    ),
)
def test_private_directory_rejects_ambiguous_lexical_paths(
    path: Path,
) -> None:
    with pytest.raises(PermissionError, match="unsafe application path"):
        ensure_private_directory(path)
