from __future__ import annotations

import asyncio
import contextlib
import errno
import fcntl
import functools
import gc
import inspect
import io
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
    ActivatedModel,
    ModelRegistry,
    ModelVerificationError,
    VerifiedModelFile,
)
from typer.testing import CliRunner


def _owned_descriptor(value: object) -> int:
    """Return the descriptor borrowed from one test-observed resource owner."""
    if isinstance(value, int):
        return value
    if isinstance(value, OwnedDirectory):
        return value.fd
    if isinstance(value, VerifiedModelFile):
        return value.fd
    if isinstance(value, ActivatedModel):
        return value.files[0].fd
    if isinstance(value, registry_module.PreadOnlyModelReader):
        return value._PreadOnlyModelReader__descriptor_owner.fileno()
    owner = getattr(value, "owner", None)
    if owner is not None:
        return _owned_descriptor(owner)
    fileno = getattr(value, "fileno", None)
    if callable(fileno):
        return int(fileno())
    raise AssertionError(f"trace did not expose a descriptor owner: {type(value)!r}")


def _assert_retained_traceback_closes_returned_owner(
    invoke: object,
    traced_method: object,
    *,
    owner_slot_name: str,
    accept_frame: object | None = None,
) -> None:
    """Interrupt one resource factory return and prove its caller-owned slot cleans up."""
    primary = KeyboardInterrupt(
        f"scripted retained-traceback interruption in {traced_method.__qualname__}"  # type: ignore[attr-defined]
    )
    descriptors: list[int] = []
    trace_reached = False

    def interrupt_return(frame: object, event: str, argument: object) -> object:
        nonlocal trace_reached
        frame_matches = frame.f_code is traced_method.__code__  # type: ignore[attr-defined]
        predicate_matches = frame_matches and (
            accept_frame is None or accept_frame(frame)  # type: ignore[operator]
        )
        if not trace_reached and event == "return" and frame_matches and predicate_matches:
            trace_reached = True
            owner = argument
            if owner is None or isinstance(owner, bool):
                owner = frame.f_locals[owner_slot_name]  # type: ignore[attr-defined]
            descriptors.append(_owned_descriptor(owner))
            raise primary
        return interrupt_return

    previous_trace = sys.gettrace()
    caught: BaseException | None = None
    try:
        sys.settrace(interrupt_return)
        result = invoke()  # type: ignore[operator]
    except BaseException as error:
        caught = error
    else:
        close = getattr(result, "close", None)
        if callable(close):
            close()
    finally:
        sys.settrace(previous_trace)

    assert caught is primary
    assert trace_reached
    assert len(descriptors) == 1
    caught.__traceback__ = None
    gc.collect()

    leaked: list[int] = []
    for descriptor in descriptors:
        try:
            os.fstat(descriptor)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            leaked.append(descriptor)
            os.close(descriptor)
    assert leaked == []


def _assert_retained_traceback_closes_callsite_owner(
    invoke: object,
    traced_method: object,
    owner_name: str,
    *,
    accept_frame: object | None = None,
) -> None:
    """Interrupt the first caller line that can observe an acquired owner."""
    primary = KeyboardInterrupt(f"scripted first-caller-line interruption for {owner_name}")
    descriptors: list[int] = []
    trace_reached = False

    def interrupt_first_caller_line(frame: object, event: str, _argument: object) -> object:
        nonlocal trace_reached
        if trace_reached or event != "line" or frame.f_code is not traced_method.__code__:  # type: ignore[attr-defined]
            return interrupt_first_caller_line
        if accept_frame is not None and not accept_frame(frame):  # type: ignore[operator]
            return interrupt_first_caller_line
        local = frame.f_locals  # type: ignore[attr-defined]
        owner = local.get(owner_name)
        if owner is None:
            owner = local.get(f"{owner_name}_slot")
        if owner is None:
            return interrupt_first_caller_line
        try:
            descriptor = _owned_descriptor(owner)
            os.fstat(descriptor)
        except (AssertionError, OSError):
            return interrupt_first_caller_line
        trace_reached = True
        descriptors.append(descriptor)
        raise primary

    previous_trace = sys.gettrace()
    caught: BaseException | None = None
    try:
        sys.settrace(interrupt_first_caller_line)
        result = invoke()  # type: ignore[operator]
    except BaseException as error:
        caught = error
    else:
        close = getattr(result, "close", None)
        if callable(close):
            close()
    finally:
        sys.settrace(previous_trace)

    assert caught is primary
    assert trace_reached
    assert len(descriptors) == 1
    caught.__traceback__ = None
    gc.collect()

    leaked: list[int] = []
    for descriptor in descriptors:
        try:
            os.fstat(descriptor)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            leaked.append(descriptor)
            os.close(descriptor)
    assert leaked == []


def _assert_trace_interrupted_close_is_retry_safe(
    close: object,
    traced_method: object,
    descriptors: tuple[int, ...],
    reports_closed: object,
) -> None:
    """Interrupt an ownership-erased/live-resource gap, or the safe close return."""
    primary = KeyboardInterrupt(
        f"scripted close transfer interruption in {traced_method.__qualname__}"  # type: ignore[attr-defined]
    )
    trace_reached = False

    def descriptor_is_open(descriptor: int) -> bool:
        try:
            os.fstat(descriptor)
        except OSError as error:
            assert error.errno == errno.EBADF
            return False
        return True

    def interrupt_close(frame: object, event: str, _argument: object) -> object:
        nonlocal trace_reached
        if trace_reached or frame.f_code is not traced_method.__code__:  # type: ignore[attr-defined]
            return interrupt_close
        unsafe_gap = (
            event == "line"
            and reports_closed()  # type: ignore[operator]
            and any(descriptor_is_open(descriptor) for descriptor in descriptors)
        )
        if unsafe_gap or event == "return":
            trace_reached = True
            raise primary
        return interrupt_close

    previous_trace = sys.gettrace()
    caught: BaseException | None = None
    try:
        sys.settrace(interrupt_close)
        close()  # type: ignore[operator]
    except BaseException as error:
        caught = error
    finally:
        sys.settrace(previous_trace)

    assert trace_reached
    assert caught is primary
    close()  # type: ignore[operator]
    caught.__traceback__ = None
    gc.collect()
    assert not any(descriptor_is_open(descriptor) for descriptor in descriptors)


def _fresh_activation_probe(governed_model_case: object) -> subprocess.CompletedProcess[str]:
    program = (
        "from pathlib import Path\n"
        "import sys\n"
        "from tuntun_core.services.models.registry import ModelRegistry\n"
        "registry=ModelRegistry.load(Path(sys.argv[1]),model_root=Path(sys.argv[2]))\n"
        "try:\n"
        "    activated=registry.activate(sys.argv[3])\n"
        "except RuntimeError:\n"
        "    raise SystemExit(1)\n"
        "activated.close()\n"
        "raise SystemExit(0)\n"
    )
    return subprocess.run(
        [
            sys.executable,
            "-c",
            program,
            str(governed_model_case.manifest),  # type: ignore[attr-defined]
            str(governed_model_case.model_root),  # type: ignore[attr-defined]
            governed_model_case.model_id,  # type: ignore[attr-defined]
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


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


@pytest.mark.parametrize(
    "operation",
    ("revision_symlink", "swap_revision_during_open"),
)
def test_revision_swap_fixture_is_portable_to_strict_source_permissions(
    governed_model_case: object,
    runtime_adapter: object,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    case = governed_model_case
    revision = case._revision_path()  # type: ignore[attr-defined]
    observed_source_modes: list[int] = []
    original_rename = Path.rename

    def require_writable_source(path: Path, target: Path) -> Path:
        if path == revision:
            source_mode = stat.S_IMODE(path.stat().st_mode)
            observed_source_modes.append(source_mode)
            if not source_mode & stat.S_IWUSR:
                raise PermissionError(errno.EACCES, "strict source is not writable", path)
        return original_rename(path, target)

    monkeypatch.setattr(Path, "rename", require_writable_source)
    if operation == "revision_symlink":
        case.apply_filesystem_mutation(operation)  # type: ignore[attr-defined]
    else:
        result = case.race_activation(operation, runtime_adapter)  # type: ignore[attr-defined]
        assert result.failed_closed  # type: ignore[attr-defined]

    assert observed_source_modes == [0o700]
    backup_name = "revision-backup" if operation == "revision_symlink" else "race-revision"
    backup = revision.parent / backup_name
    assert stat.S_IMODE(backup.stat().st_mode) == 0o500


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
    assert runtime_adapter.path_opens == []  # type: ignore[attr-defined]


def test_fresh_install_wrapper_failure_closes_download_descriptor_once(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    retained_descriptor: list[int] = []
    close_attempts: list[int] = []
    real_close = os.close

    def fail_from_manifest(
        _cls: type[VerifiedModelFile],
        _item: object,
        descriptor_slot: object,
        _owner_slot: object,
    ) -> None:
        retained_descriptor.append(_owned_descriptor(descriptor_slot))
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
        _cls: type[VerifiedModelFile],
        _item: object,
        descriptor_slot: object,
        _owner_slot: object,
    ) -> None:
        retained_descriptor.append(_owned_descriptor(descriptor_slot))
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
        _cls: type[VerifiedModelFile],
        item: object,
        descriptor_slot: object,
        owner_slot: object,
    ) -> None:
        real_from_manifest(item, descriptor_slot, owner_slot)  # type: ignore[arg-type]
        handle = owner_slot.owner  # type: ignore[attr-defined]
        assert isinstance(handle, VerifiedModelFile)
        retained_handle.append(handle)

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


def test_fresh_install_file_exists_transfer_fault_closes_slot_owner(
    governed_model_case: object,
) -> None:
    primary = FileExistsError("scripted pre-retention file-exists fault")

    def fail_transfer(point: str) -> None:
        if point == "before_retain_downloaded_file":
            raise primary

    with pytest.raises(RuntimeError, match="model install publication disappeared"):
        governed_model_case._installer(fault_hook=fail_transfer).install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )

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
        owner_slot: object,
        *,
        mode: int = 0o600,
        expected_mode: int | None = None,
    ) -> None:
        real_open(  # type: ignore[arg-type]
            directory,
            name,
            flags,
            owner_slot,
            mode=mode,
            expected_mode=expected_mode,
        )
        descriptor = _owned_descriptor(owner_slot)
        if flags & os.O_ACCMODE == os.O_WRONLY:
            write_descriptors.append(descriptor)

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


def test_close_then_error_never_retries_against_a_recycled_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owned_path = tmp_path / "owned.bin"
    replacement_path = tmp_path / "replacement.bin"
    owned_path.write_bytes(b"owned")
    replacement_path.write_bytes(b"replacement")
    owner = fs_module._FileDescriptorOwner()
    owner.open_at(owned_path, owned_path, os.O_RDONLY, 0)
    descriptor = owner.fileno()
    real_close = os.close
    real_open = os.open
    injected = False
    recycled = False

    def close_then_recycle(candidate: int) -> None:
        nonlocal injected, recycled
        if candidate == descriptor and not injected:
            injected = True
            real_close(candidate)
            replacement = real_open(replacement_path, os.O_RDONLY)
            if replacement != descriptor:
                os.dup2(replacement, descriptor)
                real_close(replacement)
            recycled = True
            raise OSError("scripted close-after-consume failure")
        real_close(candidate)

    monkeypatch.setattr(os, "close", close_then_recycle)
    primary = KeyboardInterrupt("scripted primary failure")
    fs_module.close_preserving_primary(owner, fs_module._FileDescriptorOwner.close, primary)
    owner.close()

    assert injected
    assert recycled
    assert primary.__notes__ == ["additional descriptor cleanup failure"]
    assert os.fstat(descriptor).st_size == len(b"replacement")
    real_close(descriptor)


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


class _ImmediateTlsContext:
    def __init__(self, wrapped: _HandshakeSocket) -> None:
        self.wrapped = wrapped

    def wrap_socket(self, _raw: _HandshakeSocket, *, server_hostname: str) -> _HandshakeSocket:
        assert server_hostname == "models.example.test"
        return self.wrapped


@pytest.mark.parametrize("owned_local", ("raw", "wrapped"))
def test_pinned_https_connect_retained_traceback_closes_each_socket_owner(
    monkeypatch: pytest.MonkeyPatch,
    owned_local: str,
) -> None:
    raw = _HandshakeSocket()
    wrapped = _HandshakeSocket()
    tls = _ImmediateTlsContext(wrapped)
    monkeypatch.setattr(network_module.ssl, "create_default_context", lambda: tls)
    monkeypatch.setattr(
        network_module.socket,
        "create_connection",
        lambda _address, _timeout: raw,
    )
    connection = network_module._PinnedHTTPSConnection(
        "models.example.test",
        "8.8.8.8",
        1.0,
        time.monotonic() + 1.0,
    )
    primary = KeyboardInterrupt(f"scripted {owned_local} socket transfer interruption")
    trace_reached = False

    def interrupt_transfer(frame: object, event: str, _argument: object) -> object:
        nonlocal trace_reached
        if (
            not trace_reached
            and event == "line"
            and frame.f_code is network_module._PinnedHTTPSConnection.connect.__code__  # type: ignore[attr-defined]
            and frame.f_locals.get(owned_local) is (raw if owned_local == "raw" else wrapped)  # type: ignore[attr-defined]
        ):
            trace_reached = True
            raise primary
        return interrupt_transfer

    previous_trace = sys.gettrace()
    caught: BaseException | None = None
    try:
        sys.settrace(interrupt_transfer)
        connection.connect()
    except BaseException as error:
        caught = error
    finally:
        sys.settrace(previous_trace)
        connection.close()

    assert trace_reached
    assert caught is primary
    caught.__traceback__ = None
    gc.collect()
    observed = raw if owned_local == "raw" else wrapped
    assert observed.closed.is_set()


@pytest.mark.parametrize("owned_local", ("raw", "wrapped"))
def test_pinned_https_connect_traceback_release_leaves_no_socket_descriptor(
    monkeypatch: pytest.MonkeyPatch,
    owned_local: str,
) -> None:
    raw, peer = socket.socketpair()
    wrapped = socket.socket(fileno=os.dup(raw.fileno()))
    raw_descriptor = raw.fileno()
    wrapped_descriptor = wrapped.fileno()
    tls = _ImmediateTlsContext(wrapped)  # type: ignore[arg-type]
    monkeypatch.setattr(network_module.ssl, "create_default_context", lambda: tls)
    monkeypatch.setattr(
        network_module.socket,
        "create_connection",
        lambda _address, _timeout: raw,
    )
    connection = network_module._PinnedHTTPSConnection(
        "models.example.test",
        "8.8.8.8",
        1.0,
        time.monotonic() + 1.0,
    )
    primary = KeyboardInterrupt(f"scripted {owned_local} socket descriptor interruption")
    trace_reached = False

    def interrupt_transfer(frame: object, event: str, _argument: object) -> object:
        nonlocal trace_reached
        expected = raw if owned_local == "raw" else wrapped
        if (
            not trace_reached
            and event == "line"
            and frame.f_code is network_module._PinnedHTTPSConnection.connect.__code__  # type: ignore[attr-defined]
            and frame.f_locals.get(owned_local) is expected  # type: ignore[attr-defined]
        ):
            trace_reached = True
            raise primary
        return interrupt_transfer

    previous_trace = sys.gettrace()
    caught: BaseException | None = None
    try:
        sys.settrace(interrupt_transfer)
        connection.connect()
    except BaseException as error:
        caught = error
    finally:
        sys.settrace(previous_trace)
        connection.close()

    try:
        assert trace_reached
        assert caught is primary
        caught.__traceback__ = None
        gc.collect()
        checked = (
            (raw_descriptor,)
            if owned_local == "raw"
            else (
                raw_descriptor,
                wrapped_descriptor,
            )
        )
        for descriptor in checked:
            with pytest.raises(OSError) as closed:
                os.fstat(descriptor)
            assert closed.value.errno == errno.EBADF
    finally:
        raw.close()
        wrapped.close()
        peer.close()


class _TraceResponse:
    status = 200
    headers: dict[str, str] = {}


class _TraceConnection:
    instances: list[_TraceConnection] = []

    def __init__(self, *_args: object) -> None:
        self.closed = False
        self.sock = _HandshakeSocket()
        self.instances.append(self)

    def request(self, *_args: object, **_kwargs: object) -> None:
        return None

    def getresponse(self) -> _TraceResponse:
        return _TraceResponse()

    def close(self) -> None:
        self.closed = True
        self.sock.close()


class _TraceTimer:
    instances: list[_TraceTimer] = []

    def __init__(self, _remaining: float, _callback: object) -> None:
        self.daemon = False
        self.started = False
        self.cancelled = False
        self.instances.append(self)

    def start(self) -> None:
        self.started = True

    def cancel(self) -> None:
        self.cancelled = True


@pytest.mark.parametrize(
    "traced_method",
    (
        network_module.PinnedHttpsTransport.stream_exact.__wrapped__,
        contextlib._GeneratorContextManager.__enter__,
    ),
    ids=("generator-yield", "contextmanager-enter"),
)
def test_stream_context_retained_traceback_releases_connection_and_timer(
    monkeypatch: pytest.MonkeyPatch,
    traced_method: object,
) -> None:
    _TraceConnection.instances.clear()
    _TraceTimer.instances.clear()
    monkeypatch.setattr(network_module, "_PinnedHTTPSConnection", _TraceConnection)
    monkeypatch.setattr(network_module.threading, "Timer", _TraceTimer)
    monkeypatch.setattr(
        network_module,
        "resolve_public_addresses_bounded",
        lambda _hostname, _deadline: ("8.8.8.8",),
    )
    manager = network_module.PinnedHttpsTransport().stream_exact(
        "https://models.example.test/mini.onnx",
        frozenset({"models.example.test"}),
        time.monotonic() + 1.0,
    )
    primary = KeyboardInterrupt("scripted stream context transfer interruption")
    trace_reached = False

    def interrupt_context_return(frame: object, event: str, argument: object) -> object:
        nonlocal trace_reached
        if (
            not trace_reached
            and event == "return"
            and frame.f_code is traced_method.__code__  # type: ignore[attr-defined]
            and isinstance(argument, network_module.DeadlineBoundResponse)
        ):
            trace_reached = True
            raise primary
        return interrupt_context_return

    previous_trace = sys.gettrace()
    caught: BaseException | None = None
    try:
        sys.settrace(interrupt_context_return)
        manager.__enter__()
    except BaseException as error:
        caught = error
    finally:
        sys.settrace(previous_trace)

    assert trace_reached
    assert caught is primary
    manager = None
    caught.__traceback__ = None
    gc.collect()
    assert len(_TraceConnection.instances) == 1
    assert _TraceConnection.instances[0].closed is True
    assert len(_TraceTimer.instances) == 1
    assert _TraceTimer.instances[0].cancelled is True


def test_stream_context_cancel_failure_still_closes_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _TraceConnection.instances.clear()
    _TraceTimer.instances.clear()
    monkeypatch.setattr(network_module, "_PinnedHTTPSConnection", _TraceConnection)
    monkeypatch.setattr(network_module.threading, "Timer", _TraceTimer)
    monkeypatch.setattr(
        network_module,
        "resolve_public_addresses_bounded",
        lambda _hostname, _deadline: ("8.8.8.8",),
    )

    def fail_cancel(timer: _TraceTimer) -> None:
        timer.cancelled = True
        raise OSError("scripted timer cancellation failure")

    monkeypatch.setattr(_TraceTimer, "cancel", fail_cancel)
    with (
        pytest.raises(OSError, match="scripted timer cancellation failure"),
        network_module.PinnedHttpsTransport().stream_exact(
            "https://models.example.test/mini.onnx",
            frozenset({"models.example.test"}),
            time.monotonic() + 1.0,
        ),
    ):
        pass

    assert len(_TraceConnection.instances) == 1
    assert _TraceConnection.instances[0].closed is True


@pytest.mark.parametrize("stage", ("pipe", "process", "start"))
def test_resolver_retained_traceback_closes_pipe_and_process_owners(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    context = _ResolverContext(
        poll_result=True,
        payload=("ok", ["8.8.8.8"]),
        process_alive=stage == "start",
    )
    monkeypatch.setattr(network_module.multiprocessing, "get_context", lambda _kind: context)
    primary = KeyboardInterrupt(f"scripted resolver {stage} transfer interruption")
    trace_reached = False

    def interrupt_resolver_transfer(frame: object, event: str, _argument: object) -> object:
        nonlocal trace_reached
        if (
            trace_reached
            or event != "line"
            or frame.f_code is not network_module.resolve_public_addresses_bounded.__code__  # type: ignore[attr-defined]
        ):
            return interrupt_resolver_transfer
        local = frame.f_locals  # type: ignore[attr-defined]
        reached = (
            (
                stage == "pipe"
                and local.get("receive") is context.receive
                and local.get("process") is None
            )
            or (
                stage == "process"
                and local.get("process") is context.process
                and not context.process.started
            )
            or (stage == "start" and context.process.started)
        )
        if reached:
            trace_reached = True
            raise primary
        return interrupt_resolver_transfer

    previous_trace = sys.gettrace()
    caught: BaseException | None = None
    try:
        sys.settrace(interrupt_resolver_transfer)
        network_module.resolve_public_addresses_bounded(
            "models.example.test",
            time.monotonic() + 1.0,
        )
    except BaseException as error:
        caught = error
    finally:
        sys.settrace(previous_trace)

    assert trace_reached
    assert caught is primary
    caught.__traceback__ = None
    gc.collect()
    assert context.receive.closed is True
    assert context.send.closed is True
    assert context.process.close_calls == (0 if stage == "pipe" else 1)
    if stage == "start":
        assert context.process.alive is False


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
    root_slot = fs_module._OwnedDirectoryOwnerSlot()
    OwnedDirectory.open(root_path, root_slot)
    root = root_slot.owner
    assert root is not None
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
        owner_slot: object,
        *,
        mode: int = 0o600,
        expected_mode: int | None = None,
    ) -> None:
        nonlocal lock_descriptor
        real_open_regular(
            directory,
            name,
            flags,
            owner_slot,  # type: ignore[arg-type]
            mode=mode,
            expected_mode=expected_mode,
        )
        descriptor = _owned_descriptor(owner_slot)
        if fault_active and name == lock_name:
            lock_descriptor = descriptor

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
    lock_slot = fs_module._FileDescriptorOwnerSlot()
    try:
        with root.lock(lock_name, lock_slot, timeout_seconds=1.0):
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

    retry_lock_slot = fs_module._FileDescriptorOwnerSlot()
    with root.lock(lock_name, retry_lock_slot, timeout_seconds=1.0):
        pass
    root.close()


@pytest.mark.parametrize(
    ("phase", "cleanup_fault"),
    (
        ("fresh", "stage_close"),
        ("fresh", "model_close"),
        ("fresh", "unlock"),
        ("fresh", "lock_close"),
        ("fresh", "root_close"),
        ("reuse", "model_close"),
        ("reuse", "unlock"),
        ("reuse", "lock_close"),
        ("reuse", "root_close"),
    ),
)
def test_install_cleanup_failure_closes_unreturned_activation_once(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    cleanup_fault: str,
) -> None:
    if phase == "reuse":
        installed = governed_model_case.install()  # type: ignore[attr-defined]
        installed.close()

    model_root = governed_model_case.model_root  # type: ignore[attr-defined]
    model_path = model_root / governed_model_case.model_id  # type: ignore[attr-defined]
    revision_path = model_path / ("a" * 40)
    root_metadata = model_root.stat(follow_symlinks=False)
    model_metadata = model_path.stat(follow_symlinks=False)
    root_identity = (root_metadata.st_dev, root_metadata.st_ino)
    model_identity = (model_metadata.st_dev, model_metadata.st_ino)
    primary = OSError(f"scripted install {cleanup_fault} failure")
    secondary = OSError("scripted activation cleanup failure")
    candidates: list[ActivatedModel] = []
    candidate_descriptors: list[int] = []
    activation_close_attempts: list[int] = []
    lock_descriptor: int | None = None
    fault_injected = False
    faults_active = True
    real_from_manifest = ActivatedModel.from_manifest
    real_activated_close = ActivatedModel.close
    real_open_regular = fs_module.open_regular_at
    real_flock = fcntl.flock
    real_os_close = os.close
    real_directory_close = OwnedDirectory.close
    lock_name = fs_module.model_install_lock_name(  # type: ignore[attr-defined]
        governed_model_case.model_id
    )

    def capture_activation(
        _cls: type[ActivatedModel],
        entry: object,
        files: tuple[VerifiedModelFile, ...],
        owner_slot: object,
    ) -> None:
        real_from_manifest(entry, files, owner_slot)  # type: ignore[arg-type]
        candidate = owner_slot.owner  # type: ignore[attr-defined]
        assert isinstance(candidate, ActivatedModel)
        candidates.append(candidate)
        candidate_descriptors.extend(item.fd for item in candidate.files)

    def capture_lock_descriptor(
        directory: OwnedDirectory,
        name: str,
        flags: int,
        owner_slot: object,
        *,
        mode: int = 0o600,
        expected_mode: int | None = None,
    ) -> None:
        nonlocal lock_descriptor
        real_open_regular(
            directory,
            name,
            flags,
            owner_slot,  # type: ignore[arg-type]
            mode=mode,
            expected_mode=expected_mode,
        )
        descriptor = _owned_descriptor(owner_slot)
        if name == lock_name:
            lock_descriptor = descriptor

    def fail_unlock(descriptor: int, operation: int) -> None:
        nonlocal fault_injected
        real_flock(descriptor, operation)
        if (
            faults_active
            and candidates
            and cleanup_fault == "unlock"
            and descriptor == lock_descriptor
            and operation == fcntl.LOCK_UN
            and not fault_injected
        ):
            fault_injected = True
            raise primary

    def fail_lock_close(descriptor: int) -> None:
        nonlocal fault_injected
        target = (
            faults_active
            and candidates
            and cleanup_fault == "lock_close"
            and descriptor == lock_descriptor
            and not fault_injected
        )
        real_os_close(descriptor)
        if target:
            fault_injected = True
            raise primary

    def fail_directory_close(directory: OwnedDirectory) -> None:
        nonlocal fault_injected
        identity = (directory.identity.device, directory.identity.inode)
        target_identity: tuple[int, int] | None = None
        if cleanup_fault == "root_close":
            target_identity = root_identity
        elif cleanup_fault == "model_close":
            target_identity = model_identity
        elif cleanup_fault == "stage_close" and revision_path.exists():
            revision_metadata = revision_path.stat(follow_symlinks=False)
            target_identity = (revision_metadata.st_dev, revision_metadata.st_ino)
        target = (
            faults_active
            and candidates
            and target_identity is not None
            and identity == target_identity
            and not fault_injected
        )
        real_directory_close(directory)
        if target:
            fault_injected = True
            raise primary

    def fail_activation_close(candidate: ActivatedModel) -> None:
        if any(candidate is captured for captured in candidates):
            activation_close_attempts.append(id(candidate))
            real_activated_close(candidate)
            raise secondary
        real_activated_close(candidate)

    monkeypatch.setattr(
        ActivatedModel,
        "from_manifest",
        classmethod(capture_activation),
    )
    monkeypatch.setattr(ActivatedModel, "close", fail_activation_close)
    monkeypatch.setattr(fs_module, "open_regular_at", capture_lock_descriptor)
    monkeypatch.setattr(fcntl, "flock", fail_unlock)
    monkeypatch.setattr(os, "close", fail_lock_close)
    monkeypatch.setattr(OwnedDirectory, "close", fail_directory_close)

    caught: BaseException | None = None
    try:
        try:
            unexpected = governed_model_case._installer().install(  # type: ignore[attr-defined]
                governed_model_case.model_id  # type: ignore[attr-defined]
            )
        except BaseException as error:
            caught = error
        else:
            unexpected.close()

        assert caught is primary
        assert fault_injected
        assert len(candidates) == 1
        assert activation_close_attempts == [id(candidates[0])]
        assert len(candidate_descriptors) == 1
        with pytest.raises(OSError):
            os.fstat(candidate_descriptors[0])
        assert getattr(primary, "__notes__", []) == ["additional descriptor cleanup failure"]
        assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]
    finally:
        faults_active = False
        for candidate in candidates:
            real_activated_close(candidate)


@pytest.mark.parametrize("entrypoint", ("installer", "registry"))
@pytest.mark.parametrize(
    "exception_type",
    (KeyboardInterrupt, SystemExit, GeneratorExit, asyncio.CancelledError),
)
def test_committed_reuse_preserves_control_flow_and_immutable_state(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    entrypoint: str,
    exception_type: type[BaseException],
) -> None:
    installed = governed_model_case.install()  # type: ignore[attr-defined]
    installed.close()
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    primary = exception_type(f"scripted {entrypoint} committed reuse interruption")

    def interrupt_activation(*_args: object, **_kwargs: object) -> None:
        raise primary

    monkeypatch.setattr(
        ModelRegistry,
        "_activate_from_open_model",
        staticmethod(interrupt_activation),
    )

    caught: BaseException | None = None
    try:
        if entrypoint == "installer":
            unexpected = governed_model_case._installer().install(  # type: ignore[attr-defined]
                governed_model_case.model_id  # type: ignore[attr-defined]
            )
        else:
            unexpected = governed_model_case.registry.activate(  # type: ignore[attr-defined]
                governed_model_case.model_id  # type: ignore[attr-defined]
            )
    except BaseException as error:
        caught = error
    else:
        unexpected.close()

    assert caught is primary
    assert not marker_path.exists()
    assert proof_path.exists()
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    fresh = _fresh_activation_probe(governed_model_case)
    assert fresh.returncode == 0, fresh.stderr
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("entrypoint", ("installer", "registry"))
def test_private_activation_return_interruption_closes_transaction_owned_result(
    governed_model_case: object,
    entrypoint: str,
) -> None:
    installed = governed_model_case.install()  # type: ignore[attr-defined]
    installed.close()
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    primary = KeyboardInterrupt(f"scripted {entrypoint} activation return interruption")
    traced_method = ModelRegistry._activate_from_open_model
    candidates: list[ActivatedModel] = []
    artifact_descriptors: list[int] = []
    trace_reached = False

    def interrupt_activation_return(
        frame: object,
        event: str,
        argument: object,
    ) -> object:
        nonlocal trace_reached
        if event == "return" and frame.f_code is traced_method.__code__:  # type: ignore[attr-defined]
            trace_reached = True
            candidate = argument
            if not isinstance(candidate, ActivatedModel):
                assert argument is None
                owner_slot = frame.f_locals["activated_slot"]  # type: ignore[attr-defined]
                candidate = owner_slot.owner
            assert isinstance(candidate, ActivatedModel)
            candidates.append(candidate)
            artifact_descriptors.extend(item.fd for item in candidate.files)
            raise primary
        return interrupt_activation_return

    previous_trace = sys.gettrace()
    caught: BaseException | None = None
    try:
        sys.settrace(interrupt_activation_return)
        if entrypoint == "installer":
            unexpected = governed_model_case._installer().install(  # type: ignore[attr-defined]
                governed_model_case.model_id  # type: ignore[attr-defined]
            )
        else:
            unexpected = governed_model_case.registry.activate(  # type: ignore[attr-defined]
                governed_model_case.model_id  # type: ignore[attr-defined]
            )
    except BaseException as error:
        caught = error
    else:
        unexpected.close()
    finally:
        sys.settrace(previous_trace)

    leaked_descriptors: list[int] = []
    for descriptor in artifact_descriptors:
        try:
            os.fstat(descriptor)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            leaked_descriptors.append(descriptor)
    for candidate in candidates:
        candidate.close()
    if caught is not None:
        caught.__traceback__ = None
    gc.collect()

    assert caught is primary
    assert trace_reached
    assert len(candidates) == 1
    assert len(artifact_descriptors) == 1
    assert leaked_descriptors == []
    assert not marker_path.exists()
    assert proof_path.exists()
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    fresh = _fresh_activation_probe(governed_model_case)
    assert fresh.returncode == 0, fresh.stderr
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


def test_private_reuse_return_interruption_closes_transaction_owned_result(
    governed_model_case: object,
) -> None:
    installed = governed_model_case.install()  # type: ignore[attr-defined]
    installed.close()
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    primary = KeyboardInterrupt("scripted private reuse return interruption")
    traced_method = ModelInstaller._reuse_or_recover_revision
    candidates: list[ActivatedModel] = []
    artifact_descriptors: list[int] = []
    trace_reached = False

    def interrupt_reuse_return(
        frame: object,
        event: str,
        argument: object,
    ) -> object:
        nonlocal trace_reached
        if event == "return" and frame.f_code is traced_method.__code__:  # type: ignore[attr-defined]
            trace_reached = True
            candidate = argument
            if not isinstance(candidate, ActivatedModel):
                assert argument is True
                owner_slot = frame.f_locals["activated_slot"]  # type: ignore[attr-defined]
                candidate = owner_slot.owner
            assert isinstance(candidate, ActivatedModel)
            candidates.append(candidate)
            artifact_descriptors.extend(item.fd for item in candidate.files)
            raise primary
        return interrupt_reuse_return

    previous_trace = sys.gettrace()
    caught: BaseException | None = None
    try:
        sys.settrace(interrupt_reuse_return)
        unexpected = governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
    except BaseException as error:
        caught = error
    else:
        unexpected.close()
    finally:
        sys.settrace(previous_trace)

    leaked_descriptors: list[int] = []
    for descriptor in artifact_descriptors:
        try:
            os.fstat(descriptor)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            leaked_descriptors.append(descriptor)
    for candidate in candidates:
        candidate.close()
    if caught is not None:
        caught.__traceback__ = None
    gc.collect()

    assert caught is primary
    assert trace_reached
    assert len(candidates) == 1
    assert len(artifact_descriptors) == 1
    assert leaked_descriptors == []
    assert not marker_path.exists()
    assert proof_path.exists()
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    fresh = _fresh_activation_probe(governed_model_case)
    assert fresh.returncode == 0, fresh.stderr
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("resource_factory", "scenario"),
    (
        ("directory_walk", "fresh"),
        ("directory_open_or_create", "fresh"),
        ("directory_open", "activate"),
        ("model_child", "fresh"),
        ("stage_child", "fresh"),
        ("revision_child", "activate"),
        ("existing_revision", "reuse"),
        ("lock_file", "fresh"),
        ("download_write_file", "fresh"),
        ("download_read_file", "fresh"),
        ("publication_proof_file", "activate"),
        ("activation_artifact_file", "activate"),
        ("publication_proof", "activate"),
        ("download", "fresh"),
        ("verified_file_factory", "activate"),
        ("runtime_duplicate", "verified"),
        ("runtime_reader_factory", "load"),
        ("manifest_file", "manifest"),
    ),
)
def test_every_internal_resource_factory_survives_retained_return_traceback(
    governed_model_case: object,
    runtime_adapter: object,
    resource_factory: str,
    scenario: str,
) -> None:
    """A helper-return interruption must leave cleanup ownership outside that helper."""
    installed: ActivatedModel | None = None
    if scenario in {"activate", "reuse", "verified", "load"}:
        installed = governed_model_case.install()  # type: ignore[attr-defined]
        installed.close()

    def accepts(frame: object) -> bool:
        local = frame.f_locals  # type: ignore[attr-defined]
        if resource_factory == "model_child":
            return local.get("name") == governed_model_case.model_id  # type: ignore[attr-defined]
        if resource_factory == "stage_child":
            name = local.get("name")
            return isinstance(name, str) and name.startswith(".stage-")
        if resource_factory == "revision_child":
            return local.get("name") == "a" * 40
        if resource_factory == "lock_file":
            name = local.get("name")
            return isinstance(name, str) and name.startswith(".model-install-")
        if resource_factory == "download_write_file":
            return (
                local.get("name") == "mini.onnx"
                and (int(local["flags"]) & os.O_ACCMODE) == os.O_WRONLY
            )
        if resource_factory == "download_read_file":
            return (
                local.get("name") == "mini.onnx"
                and (int(local["flags"]) & os.O_ACCMODE) == os.O_RDONLY
                and local.get("expected_mode") == 0o600
            )
        if resource_factory == "publication_proof_file":
            name = local.get("name")
            return isinstance(name, str) and name.startswith(".publication-verified-")
        if resource_factory == "activation_artifact_file":
            return local.get("name") == "mini.onnx" and local.get("expected_mode") == 0o400
        if resource_factory == "manifest_file":
            return local.get("path") == governed_model_case.manifest  # type: ignore[attr-defined]
        return True

    if resource_factory == "directory_walk":
        traced_method = OwnedDirectory._walk
        slot_name = "owner_slot"
    elif resource_factory == "directory_open_or_create":
        traced_method = OwnedDirectory.open_or_create
        slot_name = "owner_slot"
    elif resource_factory == "directory_open":
        traced_method = OwnedDirectory.open
        slot_name = "owner_slot"
    elif resource_factory in {"model_child", "stage_child", "revision_child"}:
        traced_method = OwnedDirectory.child
        slot_name = "owner_slot"
    elif resource_factory == "existing_revision":
        traced_method = ModelInstaller._open_existing_revision
        slot_name = "owner_slot"
    elif resource_factory in {
        "lock_file",
        "download_write_file",
        "download_read_file",
        "publication_proof_file",
        "activation_artifact_file",
    }:
        traced_method = fs_module.open_regular_at
        slot_name = "owner_slot"
    elif resource_factory == "publication_proof":
        traced_method = fs_module.open_publication_commit
        slot_name = "owner_slot"
    elif resource_factory == "download":
        traced_method = ModelInstaller._download
        slot_name = "owner_slot"
    elif resource_factory == "verified_file_factory":
        traced_method = VerifiedModelFile.from_manifest
        slot_name = "owner_slot"
    elif resource_factory == "runtime_duplicate":
        traced_method = VerifiedModelFile._duplicate
        slot_name = "owner_slot"
    elif resource_factory == "runtime_reader_factory":
        traced_method = registry_module.PreadOnlyModelReader.from_descriptor_owner
        slot_name = "owner_slot"
    else:
        traced_method = fs_module._FileDescriptorOwner.open_at
        slot_name = "self"

    if scenario == "activate":
        invoke = functools.partial(
            governed_model_case.registry.activate,  # type: ignore[attr-defined]
            governed_model_case.model_id,  # type: ignore[attr-defined]
        )
    elif scenario == "reuse":
        invoke = functools.partial(
            governed_model_case._installer().install,  # type: ignore[attr-defined]
            governed_model_case.model_id,  # type: ignore[attr-defined]
        )
    elif scenario == "verified":
        active = governed_model_case.registry.activate(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
        invoke = active.files[0].verified
    elif scenario == "load":
        active = governed_model_case.registry.activate(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
        invoke = functools.partial(active.files[0].load_with, runtime_adapter)
    elif scenario == "manifest":
        invoke = functools.partial(
            ModelRegistry.load,
            governed_model_case.manifest,  # type: ignore[attr-defined]
        )
    else:
        invoke = functools.partial(
            governed_model_case._installer().install,  # type: ignore[attr-defined]
            governed_model_case.model_id,  # type: ignore[attr-defined]
        )

    try:
        _assert_retained_traceback_closes_returned_owner(
            invoke,
            traced_method,
            owner_slot_name=slot_name,
            accept_frame=accepts,
        )
    finally:
        if scenario in {"verified", "load"}:
            active.close()

    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("owner_name", ("root", "model", "stage"))
def test_install_first_caller_line_retains_every_directory_owner_for_cleanup(
    governed_model_case: object,
    owner_name: str,
) -> None:
    invoke = functools.partial(
        governed_model_case._installer().install,  # type: ignore[attr-defined]
        governed_model_case.model_id,  # type: ignore[attr-defined]
    )

    _assert_retained_traceback_closes_callsite_owner(
        invoke,
        ModelInstaller.install,
        owner_name,
    )

    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("operation", ("activate", "install"))
def test_public_lease_pre_detach_line_retains_activation_for_cleanup(
    governed_model_case: object,
    operation: str,
) -> None:
    if operation == "activate":
        installed = governed_model_case.install()  # type: ignore[attr-defined]
        installed.close()
        tracked_activate = ModelRegistry.activate
        original_activate = inspect.getclosurevars(tracked_activate).nonlocals.get(
            "original_activate",
            tracked_activate,
        )
        invoke = functools.partial(
            original_activate,
            governed_model_case.registry,  # type: ignore[attr-defined]
            governed_model_case.model_id,  # type: ignore[attr-defined]
        )
        traced_method = original_activate
    else:
        invoke = functools.partial(
            governed_model_case._installer().install,  # type: ignore[attr-defined]
            governed_model_case.model_id,  # type: ignore[attr-defined]
        )
        traced_method = ModelInstaller.install

    _assert_retained_traceback_closes_callsite_owner(
        invoke,
        traced_method,
        "activated",
        accept_frame=lambda frame: isinstance(  # type: ignore[attr-defined]
            frame.f_locals.get("activated"),
            ActivatedModel,
        ),
    )

    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


def test_private_activation_success_tail_retains_local_owners_for_cleanup(
    governed_model_case: object,
) -> None:
    installed = governed_model_case.install()  # type: ignore[attr-defined]
    installed.close()
    tracked_activate = ModelRegistry.activate
    original_activate = inspect.getclosurevars(tracked_activate).nonlocals.get(
        "original_activate",
        tracked_activate,
    )

    def tail_reached(frame: object) -> bool:
        local = frame.f_locals  # type: ignore[attr-defined]
        activated_slot = local.get("activated_slot")
        revision_slot = local.get("revision_slot")
        return (
            local.get("handles") == []
            and activated_slot is not None
            and activated_slot.owner is not None
            and revision_slot is not None
            and revision_slot.owner is not None
        )

    _assert_retained_traceback_closes_callsite_owner(
        functools.partial(
            original_activate,
            governed_model_case.registry,  # type: ignore[attr-defined]
            governed_model_case.model_id,  # type: ignore[attr-defined]
        ),
        ModelRegistry._activate_from_open_model,
        "revision",
        accept_frame=tail_reached,
    )

    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


def test_recovery_success_tail_retains_local_revision_for_cleanup(
    governed_model_case: object,
) -> None:
    governed_model_case.crash_install_at("after_publish_before_seal")  # type: ignore[attr-defined]

    def tail_reached(frame: object) -> bool:
        local = frame.f_locals  # type: ignore[attr-defined]
        activated_slot = local.get("activated_slot")
        revision_slot = local.get("revision_slot")
        return (
            local.get("handles") == []
            and activated_slot is not None
            and activated_slot.owner is not None
            and revision_slot is not None
            and revision_slot.owner is not None
        )

    _assert_retained_traceback_closes_callsite_owner(
        functools.partial(
            governed_model_case._installer().install,  # type: ignore[attr-defined]
            governed_model_case.model_id,  # type: ignore[attr-defined]
        ),
        ModelInstaller._reuse_or_recover_revision,
        "revision",
        accept_frame=tail_reached,
    )

    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


def test_stale_publication_cleanup_retains_proof_owner_before_use(
    governed_model_case: object,
) -> None:
    governed_model_case.crash_install_at("after_publish_before_seal")  # type: ignore[attr-defined]
    governed_model_case.create_interrupted_recovery_marker()  # type: ignore[attr-defined]
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    proof_path.write_bytes(b"")
    proof_path.chmod(0o400)

    _assert_retained_traceback_closes_callsite_owner(
        functools.partial(
            governed_model_case._installer().install,  # type: ignore[attr-defined]
            governed_model_case.model_id,  # type: ignore[attr-defined]
        ),
        ModelInstaller._remove_publication_commit,
        "descriptor_owner",
    )

    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


def test_cleanup_tree_child_factory_survives_retained_return_traceback(tmp_path: Path) -> None:
    root_path = tmp_path / "model-root"
    stage_path = root_path / ".stage-trace"
    nested_path = stage_path / "nested"
    nested_path.mkdir(parents=True, mode=0o700)
    root_path.chmod(0o700)
    stage_path.chmod(0o700)
    nested_path.chmod(0o700)
    expected_stat = stage_path.stat(follow_symlinks=False)
    expected = fs_module.DirectoryIdentity(expected_stat.st_dev, expected_stat.st_ino)
    root_slot = fs_module._OwnedDirectoryOwnerSlot()
    OwnedDirectory.open(root_path, root_slot)
    root = root_slot.owner
    assert root is not None

    def accepts(frame: object) -> bool:
        return frame.f_locals.get("name") == "nested"  # type: ignore[attr-defined]

    try:
        _assert_retained_traceback_closes_returned_owner(
            lambda: root.remove_private_stage(".stage-trace", expected),
            OwnedDirectory.child,
            owner_slot_name="owner_slot",
            accept_frame=accepts,
        )
    finally:
        root.close()


@pytest.mark.parametrize(
    "owner_kind",
    ("descriptor", "directory", "reader", "verified-file", "activated-model"),
)
def test_every_descriptor_owner_close_is_safe_under_retained_line_traceback(
    governed_model_case: object,
    tmp_path: Path,
    owner_kind: str,
) -> None:
    active: ActivatedModel | None = None
    if owner_kind == "directory":
        directory_path = tmp_path / "owned-directory"
        directory_path.mkdir(mode=0o700)
        directory_slot = fs_module._OwnedDirectoryOwnerSlot()
        OwnedDirectory.open(directory_path, directory_slot)
        directory = directory_slot.owner
        assert directory is not None
        descriptor = directory.fd

        def reports_closed() -> bool:
            try:
                return directory.fd < 0
            except OSError:
                return True

        _assert_trace_interrupted_close_is_retry_safe(
            directory.close,
            OwnedDirectory.close,
            (descriptor,),
            reports_closed,
        )
        return

    active = governed_model_case.install()  # type: ignore[attr-defined]
    handle = active.files[0]
    if owner_kind == "activated-model":
        descriptors = tuple(item.fd for item in active.files)
        _assert_trace_interrupted_close_is_retry_safe(
            active.close,
            ActivatedModel.close,
            descriptors,
            lambda: active._ActivatedModel__closed[0],
        )
        return
    if owner_kind == "verified-file":
        descriptor = handle.fd

        def verified_file_reports_closed() -> bool:
            legacy = getattr(handle, "_VerifiedModelFile__descriptor", None)
            if isinstance(legacy, list):
                return bool(legacy) and legacy[0] < 0
            owner = handle._VerifiedModelFile__descriptor_owner
            return owner.fd < 0

        try:
            _assert_trace_interrupted_close_is_retry_safe(
                handle.close,
                VerifiedModelFile.close,
                (descriptor,),
                verified_file_reports_closed,
            )
        finally:
            active.close()
        return

    duplicate_slot = fs_module._FileDescriptorOwnerSlot()
    handle._duplicate(duplicate_slot)
    descriptor_owner = duplicate_slot.owner
    assert descriptor_owner is not None
    if owner_kind == "descriptor":
        descriptor = descriptor_owner.fileno()
        try:
            _assert_trace_interrupted_close_is_retry_safe(
                descriptor_owner.close,
                fs_module._FileDescriptorOwner.close,
                (descriptor,),
                lambda: descriptor_owner.fd < 0,
            )
        finally:
            active.close()
        return

    reader_slot = registry_module._PreadOnlyModelReaderOwnerSlot()
    registry_module.PreadOnlyModelReader.from_descriptor_owner(
        duplicate_slot,
        reader_slot,
        handle.size,
        handle.sha256,
    )
    reader = reader_slot.owner
    assert reader is not None
    descriptor = reader._PreadOnlyModelReader__descriptor_owner.fileno()
    try:
        _assert_trace_interrupted_close_is_retry_safe(
            reader.close,
            registry_module.PreadOnlyModelReader.close,
            (descriptor,),
            lambda: reader.closed,
        )
    finally:
        active.close()


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
        owner_slot: fs_module._FileDescriptorOwnerSlot,
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
            owner_slot,
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
        owner_slot: fs_module._FileDescriptorOwnerSlot,
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
            owner_slot,
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


def test_recovery_marker_inode_is_durable_before_atomic_read_only_authority(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    model_path = marker_path.parent
    model_metadata = model_path.stat(follow_symlinks=False)
    model_identity = (model_metadata.st_dev, model_metadata.st_ino)
    marker_identity: tuple[int, int] | None = None
    marker_fsync_modes: list[int] = []
    parent_fsync_modes: list[int] = []
    real_fsync = os.fsync
    real_directory_fsync = OwnedDirectory.fsync

    def track_fsync(descriptor: int) -> None:
        nonlocal marker_identity
        identity = os.fstat(descriptor)
        if marker_path.exists():
            marker = marker_path.stat(follow_symlinks=False)
            if (identity.st_dev, identity.st_ino) == (marker.st_dev, marker.st_ino):
                marker_identity = (identity.st_dev, identity.st_ino)
                marker_fsync_modes.append(stat.S_IMODE(identity.st_mode))
        real_fsync(descriptor)

    def track_parent_fsync(directory: OwnedDirectory) -> None:
        identity = (directory.identity.device, directory.identity.inode)
        if identity == model_identity and marker_path.exists():
            parent_fsync_modes.append(stat.S_IMODE(marker_path.stat(follow_symlinks=False).st_mode))
        real_directory_fsync(directory)

    monkeypatch.setattr(os, "fsync", track_fsync)
    monkeypatch.setattr(OwnedDirectory, "fsync", track_parent_fsync)

    activated = governed_model_case.install()  # type: ignore[attr-defined]
    activated.close()

    assert marker_fsync_modes == [0o600, 0o400]
    assert parent_fsync_modes == [0o600, 0o600, 0o400]
    assert marker_identity is not None
    proof = proof_path.stat(follow_symlinks=False)
    assert (proof.st_dev, proof.st_ino) == marker_identity


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
def test_atomic_marker_publish_rejects_source_swap_without_unsealing_ambiguity(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    if phase == "recovery":
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    displaced_path = marker_path.with_name(f".displaced-prepared-marker-{phase}")
    real_atomic_publish = installer_module.atomic_publish_dir_noreplace
    prepared_identity: tuple[int, int] | None = None
    replacement_identity: tuple[int, int] | None = None

    def swap_source_immediately_before_native_publish(
        parent: OwnedDirectory,
        source: str,
        target: str,
        **kwargs: object,
    ) -> None:
        nonlocal prepared_identity, replacement_identity
        if source == marker_path.name and target == proof_path.name:
            prepared = marker_path.stat(follow_symlinks=False)
            prepared_identity = (prepared.st_dev, prepared.st_ino)
            marker_path.rename(displaced_path)
            marker_path.write_bytes(b"")
            marker_path.chmod(0o400)
            replacement = marker_path.stat(follow_symlinks=False)
            replacement_identity = (replacement.st_dev, replacement.st_ino)
        real_atomic_publish(parent, source, target, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        installer_module,
        "atomic_publish_dir_noreplace",
        swap_source_immediately_before_native_publish,
    )

    caught: BaseException | None = None
    try:
        unexpected = governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
    except BaseException as error:
        caught = error
    else:
        unexpected.close()

    fresh = _fresh_activation_probe(governed_model_case)
    assert prepared_identity is not None
    assert replacement_identity is not None
    assert prepared_identity != replacement_identity
    assert fresh.returncode == 1, fresh.stderr
    assert isinstance(caught, PermissionError)
    assert getattr(caught, "__notes__", []) == ["additional publication commit resolution failure"]
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    assert marker_path.exists()
    assert not proof_path.exists()
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
@pytest.mark.parametrize("mutation", ("mode", "size", "link"))
def test_atomic_marker_publish_revalidates_exact_source_properties_at_native_boundary(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    mutation: str,
) -> None:
    if phase == "recovery":
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    linked_path = marker_path.with_name(f".linked-prepared-marker-{phase}")
    real_atomic_publish = installer_module.atomic_publish_dir_noreplace
    real_cdll = fs_module.ctypes.CDLL
    native_libc = real_cdll(None, use_errno=True)
    native_name = "renameatx_np" if sys.platform == "darwin" else "renameat2"
    real_native_publish = getattr(native_libc, native_name)
    transaction_witness: object | None = None
    marker_native_calls = 0

    def track_native_publish(*args: object) -> int:
        nonlocal marker_native_calls
        if args[1] == os.fsencode(marker_path.name):
            marker_native_calls += 1
        return real_native_publish(*args)

    class TrackedLibc:
        def __getattr__(self, name: str) -> object:
            if name == native_name:
                return track_native_publish
            return getattr(native_libc, name)

    def mutate_source_immediately_before_native_publish(
        parent: OwnedDirectory,
        source: str,
        target: str,
        **kwargs: object,
    ) -> None:
        nonlocal transaction_witness
        if source == marker_path.name and target == proof_path.name:
            transaction_witness = kwargs.get("witness")
            descriptor = kwargs.get("expected_source_fd")
            assert isinstance(descriptor, int)
            if mutation == "mode":
                marker_path.chmod(0o600)
            elif mutation == "size":
                assert os.pwrite(descriptor, b"x", 0) == 1
            else:
                os.link(marker_path, linked_path)
        real_atomic_publish(parent, source, target, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(fs_module.ctypes, "CDLL", lambda *_args, **_kwargs: TrackedLibc())
    monkeypatch.setattr(
        installer_module,
        "atomic_publish_dir_noreplace",
        mutate_source_immediately_before_native_publish,
    )

    caught: BaseException | None = None
    try:
        unexpected = governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
    except BaseException as error:
        caught = error
    else:
        unexpected.close()

    fresh = _fresh_activation_probe(governed_model_case)
    assert isinstance(caught, PermissionError)
    assert marker_native_calls == 0
    assert transaction_witness is not None
    assert transaction_witness.committed is False  # type: ignore[attr-defined]
    assert marker_path.exists()
    assert not proof_path.exists()
    assert governed_model_case.final_revision_mode == 0o700  # type: ignore[attr-defined]
    assert fresh.returncode == 1, fresh.stderr
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
def test_exact_fallback_proves_commit_when_wrapper_does_not_forward_witness(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    if phase == "recovery":
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    real_atomic_publish = installer_module.atomic_publish_dir_noreplace
    prepared_identity: tuple[int, int] | None = None

    def publish_without_forwarding_witness(
        parent: OwnedDirectory,
        source: str,
        target: str,
        **kwargs: object,
    ) -> None:
        nonlocal prepared_identity
        if source == marker_path.name and target == proof_path.name:
            prepared = marker_path.stat(follow_symlinks=False)
            prepared_identity = (prepared.st_dev, prepared.st_ino)
            kwargs.pop("witness", None)
        real_atomic_publish(parent, source, target, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        installer_module,
        "atomic_publish_dir_noreplace",
        publish_without_forwarding_witness,
    )

    activated = governed_model_case._installer().install(  # type: ignore[attr-defined]
        governed_model_case.model_id  # type: ignore[attr-defined]
    )
    activated.close()

    assert prepared_identity is not None
    proof = proof_path.stat(follow_symlinks=False)
    assert (proof.st_dev, proof.st_ino) == prepared_identity
    assert not marker_path.exists()
    fresh = _fresh_activation_probe(governed_model_case)
    assert fresh.returncode == 0, fresh.stderr
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
def test_conforming_publish_return_interruption_propagates_after_commit(
    governed_model_case: object,
    phase: str,
) -> None:
    if phase == "recovery":
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    primary = KeyboardInterrupt("scripted conforming publish return interruption")
    traced_method = fs_module.atomic_publish_dir_noreplace
    trace_reached = False

    def interrupt_committed_return(
        frame: object,
        event: str,
        argument: object,
    ) -> object:
        nonlocal trace_reached
        if (
            event == "return"
            and frame.f_code is traced_method.__code__  # type: ignore[attr-defined]
            and frame.f_locals.get("source") == marker_path.name  # type: ignore[attr-defined]
            and frame.f_locals.get("target") == proof_path.name  # type: ignore[attr-defined]
        ):
            trace_reached = True
            assert argument is None
            witness = frame.f_locals["witness"]  # type: ignore[attr-defined]
            assert witness is not None
            assert witness.committed  # type: ignore[attr-defined]
            raise primary
        return interrupt_committed_return

    previous_trace = sys.gettrace()
    caught: BaseException | None = None
    try:
        sys.settrace(interrupt_committed_return)
        unexpected = governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
    except BaseException as error:
        caught = error
    else:
        unexpected.close()
    finally:
        sys.settrace(previous_trace)

    assert caught is primary
    assert trace_reached
    assert not marker_path.exists()
    assert proof_path.exists()
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    fresh = _fresh_activation_probe(governed_model_case)
    assert fresh.returncode == 0, fresh.stderr
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
def test_nonforwarding_publish_control_flow_interruption_propagates_after_fallback(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    if phase == "recovery":
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    primary = KeyboardInterrupt("scripted non-forwarding publish interruption")
    real_atomic_publish = installer_module.atomic_publish_dir_noreplace
    interruption_injected = False

    def publish_without_witness_then_interrupt(
        parent: OwnedDirectory,
        source: str,
        target: str,
        **kwargs: object,
    ) -> None:
        nonlocal interruption_injected
        if source == marker_path.name and target == proof_path.name:
            kwargs.pop("witness", None)
            real_atomic_publish(parent, source, target, **kwargs)  # type: ignore[arg-type]
            interruption_injected = True
            raise primary
        real_atomic_publish(parent, source, target, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        installer_module,
        "atomic_publish_dir_noreplace",
        publish_without_witness_then_interrupt,
    )

    caught: BaseException | None = None
    try:
        unexpected = governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
    except BaseException as error:
        caught = error
    else:
        unexpected.close()

    assert caught is primary
    assert interruption_injected
    assert not marker_path.exists()
    assert proof_path.exists()
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    fresh = _fresh_activation_probe(governed_model_case)
    assert fresh.returncode == 0, fresh.stderr
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
def test_exception_path_reresolves_commit_before_fallback_witness_rollback(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    if phase == "recovery":
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    primary = KeyboardInterrupt("scripted fallback witness assignment interruption")
    real_atomic_publish = installer_module.atomic_publish_dir_noreplace
    traced_method = ModelInstaller._publish_prepared_recovery_marker
    source_lines, first_line = inspect.getsourcelines(traced_method)
    target_offset = next(
        index
        for index, line in enumerate(source_lines)
        if line.strip() == "witness.committed = True"
    )
    target_line = first_line + target_offset
    trace_reached = False

    def publish_without_forwarding_witness(
        parent: OwnedDirectory,
        source: str,
        target: str,
        **kwargs: object,
    ) -> None:
        if source == marker_path.name and target == proof_path.name:
            kwargs.pop("witness", None)
        real_atomic_publish(parent, source, target, **kwargs)  # type: ignore[arg-type]

    def interrupt_fallback_witness_assignment(
        frame: object,
        event: str,
        _argument: object,
    ) -> object:
        nonlocal trace_reached
        if (
            not trace_reached
            and event == "line"
            and frame.f_code is traced_method.__code__  # type: ignore[attr-defined]
            and frame.f_lineno == target_line  # type: ignore[attr-defined]
        ):
            trace_reached = True
            assert frame.f_locals["witness"].committed is False  # type: ignore[attr-defined]
            raise primary
        return interrupt_fallback_witness_assignment

    monkeypatch.setattr(
        installer_module,
        "atomic_publish_dir_noreplace",
        publish_without_forwarding_witness,
    )
    previous_trace = sys.gettrace()
    caught: BaseException | None = None
    try:
        sys.settrace(interrupt_fallback_witness_assignment)
        unexpected = governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
    except BaseException as error:
        caught = error
    else:
        unexpected.close()
    finally:
        sys.settrace(previous_trace)

    assert caught is primary
    assert trace_reached
    assert not marker_path.exists()
    assert proof_path.exists()
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    fresh = _fresh_activation_probe(governed_model_case)
    assert fresh.returncode == 0, fresh.stderr
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
def test_repeated_witness_interruption_preserves_inconclusive_sealed_state(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    if phase == "recovery":
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    primary = KeyboardInterrupt("scripted first witness interruption")
    secondary = KeyboardInterrupt("scripted repeated witness interruption")
    real_atomic_publish = installer_module.atomic_publish_dir_noreplace

    class InterruptingWitness:
        def __init__(self) -> None:
            self.assignment_attempts = 0

        @property
        def committed(self) -> bool:
            return False

        @committed.setter
        def committed(self, _value: bool) -> None:
            self.assignment_attempts += 1
            if self.assignment_attempts == 1:
                raise primary
            raise secondary

    witness = InterruptingWitness()

    def publish_without_forwarding_witness(
        parent: OwnedDirectory,
        source: str,
        target: str,
        **kwargs: object,
    ) -> None:
        if source == marker_path.name and target == proof_path.name:
            kwargs.pop("witness", None)
        real_atomic_publish(parent, source, target, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(installer_module, "AtomicPublishWitness", lambda: witness)
    monkeypatch.setattr(
        installer_module,
        "atomic_publish_dir_noreplace",
        publish_without_forwarding_witness,
    )

    caught: BaseException | None = None
    try:
        unexpected = governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
    except BaseException as error:
        caught = error
    else:
        unexpected.close()

    assert caught is primary
    assert witness.assignment_attempts == 2
    assert getattr(primary, "__notes__", []) == ["additional publication commit resolution failure"]
    assert not marker_path.exists()
    assert proof_path.exists()
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    fresh = _fresh_activation_probe(governed_model_case)
    assert fresh.returncode == 0, fresh.stderr
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
def test_post_helper_interruption_uses_transaction_owned_commit_witness(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    if phase == "recovery":
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    primary = KeyboardInterrupt("scripted post-helper interruption")
    real_publish = ModelInstaller._publish_prepared_recovery_marker
    transaction_witness: object | None = None

    def publish_then_interrupt(*args: object, **kwargs: object) -> None:
        nonlocal transaction_witness
        transaction_witness = kwargs.get("witness")
        real_publish(*args, **kwargs)  # type: ignore[arg-type]
        raise primary

    monkeypatch.setattr(
        ModelInstaller,
        "_publish_prepared_recovery_marker",
        staticmethod(publish_then_interrupt),
    )

    caught: BaseException | None = None
    try:
        governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
    except BaseException as error:
        caught = error

    assert caught is primary
    assert transaction_witness is not None
    assert transaction_witness.committed is True  # type: ignore[attr-defined]
    assert not marker_path.exists()
    assert proof_path.exists()
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    fresh = _fresh_activation_probe(governed_model_case)
    assert fresh.returncode == 0, fresh.stderr
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
def test_marker_descriptor_close_failure_after_commit_does_not_roll_back(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    if phase == "recovery":
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    primary = OSError("scripted committed marker descriptor close failure")
    real_acquire_marker = ModelInstaller._acquire_recovery_marker
    owner_type = installer_module._PublicationMarkerOwner
    real_owner_close = owner_type.close
    real_close = os.close
    marker_descriptors: set[int] = set()
    marker_identity: tuple[int, int] | None = None
    close_injected = False
    marker_close_argument: object | None = None
    marker_close_attempts = 0
    replacement_fd: int | None = None

    def capture_marker(
        model: OwnedDirectory,
        revision: str,
        owner_slot: installer_module._PublicationMarkerOwnerSlot,
        *,
        create: bool,
    ) -> None:
        nonlocal marker_identity
        real_acquire_marker(
            model,
            revision,
            owner_slot,
            create=create,
        )
        assert owner_slot.owner is not None
        descriptor = owner_slot.owner.fileno()
        identity = os.fstat(descriptor)
        marker_descriptors.add(descriptor)
        marker_identity = (identity.st_dev, identity.st_ino)

    def fail_committed_marker_close(owner: object) -> None:
        nonlocal close_injected, marker_close_argument, marker_close_attempts, replacement_fd
        descriptor = None if owner.closed else owner.fileno()  # type: ignore[attr-defined]
        target = descriptor in marker_descriptors or owner is marker_close_argument
        if target and descriptor is not None:
            marker_close_argument = owner
            marker_close_attempts += 1
        first_target = target and not close_injected
        released_fd = descriptor if first_target else None
        real_owner_close(owner)  # type: ignore[arg-type]
        if first_target:
            assert released_fd is not None
            replacement_fd = os.open(proof_path, os.O_RDONLY)
            assert replacement_fd == released_fd
            close_injected = True
            raise primary

    monkeypatch.setattr(
        ModelInstaller,
        "_acquire_recovery_marker",
        staticmethod(capture_marker),
    )
    monkeypatch.setattr(owner_type, "close", fail_committed_marker_close)

    caught: BaseException | None = None
    try:
        governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
    except BaseException as error:
        caught = error

    replacement_survived = False
    if replacement_fd is not None:
        try:
            os.fstat(replacement_fd)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            replacement_survived = True
            real_close(replacement_fd)

    assert caught is primary
    assert close_injected
    assert marker_close_attempts == 1
    assert marker_identity is not None
    proof = proof_path.stat(follow_symlinks=False)
    assert (proof.st_dev, proof.st_ino) == marker_identity
    assert not marker_path.exists()
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    assert replacement_fd is not None
    assert replacement_survived
    fresh = _fresh_activation_probe(governed_model_case)
    assert fresh.returncode == 0, fresh.stderr
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
@pytest.mark.parametrize("timing", ("before", "after"))
def test_committed_marker_close_fault_has_explicit_descriptor_ownership(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    timing: str,
) -> None:
    if phase == "recovery":
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    primary = KeyboardInterrupt(f"scripted {timing}-close interruption")
    real_acquire_marker = ModelInstaller._acquire_recovery_marker
    owner_type = installer_module._PublicationMarkerOwner
    real_owner_close = owner_type.close
    marker_descriptors: set[int] = set()
    marker_close_attempts: list[int] = []
    hook_reached = False

    def capture_marker(
        model: OwnedDirectory,
        revision: str,
        owner_slot: installer_module._PublicationMarkerOwnerSlot,
        *,
        create: bool,
    ) -> None:
        real_acquire_marker(
            model,
            revision,
            owner_slot,
            create=create,
        )
        assert owner_slot.owner is not None
        descriptor = owner_slot.owner.fileno()
        marker_descriptors.add(descriptor)

    def track_marker_close(owner: object) -> None:
        if not owner.closed:  # type: ignore[attr-defined]
            descriptor = owner.fileno()  # type: ignore[attr-defined]
            if descriptor in marker_descriptors:
                marker_close_attempts.append(descriptor)
        real_owner_close(owner)  # type: ignore[arg-type]

    def interrupt_close_boundary(point: str) -> None:
        nonlocal hook_reached
        if point == f"{timing}_publication_marker_close":
            hook_reached = True
            raise primary

    monkeypatch.setattr(
        ModelInstaller,
        "_acquire_recovery_marker",
        staticmethod(capture_marker),
    )
    monkeypatch.setattr(owner_type, "close", track_marker_close)

    caught: BaseException | None = None
    try:
        unexpected = governed_model_case._installer(  # type: ignore[attr-defined]
            fault_hook=interrupt_close_boundary
        ).install(governed_model_case.model_id)  # type: ignore[attr-defined]
    except BaseException as error:
        caught = error
    else:
        unexpected.close()

    assert caught is primary
    assert hook_reached
    assert len(marker_close_attempts) == 1
    assert not marker_path.exists()
    assert proof_path.exists()
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    fresh = _fresh_activation_probe(governed_model_case)
    assert fresh.returncode == 0, fresh.stderr
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
@pytest.mark.parametrize("timing", ("before_call", "after_call"))
def test_trace_interruption_at_committed_marker_close_keeps_descriptor_owned(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    timing: str,
) -> None:
    if phase == "recovery":
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    primary = KeyboardInterrupt(f"scripted trace interruption {timing}")
    real_acquire_marker = ModelInstaller._acquire_recovery_marker
    real_close = os.close
    marker_descriptors: list[int] = []
    traced_method = (
        ModelInstaller._reuse_or_recover_revision if phase == "recovery" else ModelInstaller.install
    )
    source, first_line = inspect.getsourcelines(traced_method)
    target_text = (
        "marker_owner.close()"
        if timing == "before_call"
        else 'self._fault_hook("after_publication_marker_close")'
    )
    target_offset = next(index for index, line in enumerate(source) if target_text in line)
    target_line = first_line + target_offset
    trace_reached = False

    def capture_marker(
        model: OwnedDirectory,
        revision: str,
        owner_slot: installer_module._PublicationMarkerOwnerSlot,
        *,
        create: bool,
    ) -> None:
        real_acquire_marker(
            model,
            revision,
            owner_slot,
            create=create,
        )
        assert owner_slot.owner is not None
        descriptor = owner_slot.owner.fileno()
        marker_descriptors.append(descriptor)

    def interrupt_at_close_line(
        frame: object,
        event: str,
        _argument: object,
    ) -> object:
        nonlocal trace_reached
        if (
            event == "line"
            and frame.f_code is traced_method.__code__  # type: ignore[attr-defined]
            and frame.f_lineno == target_line  # type: ignore[attr-defined]
        ):
            trace_reached = True
            raise primary
        return interrupt_at_close_line

    monkeypatch.setattr(
        ModelInstaller,
        "_acquire_recovery_marker",
        staticmethod(capture_marker),
    )
    previous_trace = sys.gettrace()
    caught: BaseException | None = None
    try:
        sys.settrace(interrupt_at_close_line)
        unexpected = governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
    except BaseException as error:
        caught = error
    else:
        unexpected.close()
    finally:
        sys.settrace(previous_trace)

    assert len(marker_descriptors) == 1
    descriptor_was_open = True
    try:
        os.fstat(marker_descriptors[0])
    except OSError as error:
        assert error.errno == errno.EBADF
        descriptor_was_open = False
    if descriptor_was_open:
        real_close(marker_descriptors[0])

    assert caught is primary
    assert trace_reached
    assert not descriptor_was_open
    assert not marker_path.exists()
    assert proof_path.exists()
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    fresh = _fresh_activation_probe(governed_model_case)
    assert fresh.returncode == 0, fresh.stderr
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


def test_publication_marker_owner_has_no_python_descriptor_transfer_callback() -> None:
    owner_type = installer_module._PublicationMarkerOwner

    assert issubclass(owner_type, io.FileIO)
    assert owner_type.close is io.FileIO.close
    assert not any("__index__" in base.__dict__ for base in owner_type.__mro__)
    assert not hasattr(ModelInstaller, "_open_recovery_marker")
    assert not hasattr(ModelInstaller, "_open_recovery_marker_owner")


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
def test_trace_interruption_at_marker_slot_acquisition_return_closes_descriptor(
    governed_model_case: object,
    phase: str,
) -> None:
    if phase == "recovery":
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    primary = KeyboardInterrupt("scripted marker-slot acquisition interruption")
    traced_method = ModelInstaller._acquire_recovery_marker
    marker_descriptors: list[int] = []
    trace_reached = False

    def interrupt_return(
        frame: object,
        event: str,
        argument: object,
    ) -> object:
        nonlocal trace_reached
        if event == "return" and frame.f_code is traced_method.__code__:  # type: ignore[attr-defined]
            trace_reached = True
            assert argument is None
            owner_slot = frame.f_locals["owner_slot"]  # type: ignore[attr-defined]
            owner = owner_slot.owner
            assert owner is not None
            marker_descriptors.append(owner.fileno())
            raise primary
        return interrupt_return

    previous_trace = sys.gettrace()
    caught: BaseException | None = None
    try:
        sys.settrace(interrupt_return)
        unexpected = governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
    except BaseException as error:
        caught = error
    else:
        unexpected.close()
    finally:
        sys.settrace(previous_trace)

    assert caught is primary
    assert trace_reached
    assert len(marker_descriptors) == 1
    descriptor = marker_descriptors[0]
    try:
        os.fstat(descriptor)
    except OSError as error:
        assert error.errno == errno.EBADF
    else:
        os.close(descriptor)
        raise AssertionError("marker descriptor remained open in retained exception traceback")

    caught.__traceback__ = None
    gc.collect()
    assert marker_path.exists()
    assert not proof_path.exists()
    assert governed_model_case.final_revision_mode == 0o700  # type: ignore[attr-defined]
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("create", (True, False), ids=("fresh", "recovery"))
def test_fileio_marker_opener_uses_exact_modes_and_cloexec(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    create: bool,
) -> None:
    if not create:
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
        governed_model_case.create_interrupted_recovery_marker()  # type: ignore[attr-defined]
    marker_name = governed_model_case.recovery_marker_path.name  # type: ignore[attr-defined]
    real_open = os.open
    observed: list[tuple[int, int, int, bool]] = []

    def capture_marker_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == marker_name and dir_fd is not None:
            observed.append((flags, mode, dir_fd, os.get_inheritable(descriptor)))
        return descriptor

    monkeypatch.setattr(os, "open", capture_marker_open)

    activated = governed_model_case._installer().install(  # type: ignore[attr-defined]
        governed_model_case.model_id  # type: ignore[attr-defined]
    )
    activated.close()

    assert len(observed) == 1
    flags, mode, dir_fd, inheritable = observed[0]
    assert flags & os.O_ACCMODE == (os.O_RDWR if create else os.O_RDONLY)
    assert bool(flags & os.O_CREAT) is create
    assert bool(flags & os.O_EXCL) is create
    cloexec = getattr(os, "O_CLOEXEC", 0)
    if cloexec:
        assert flags & cloexec
    assert mode == 0o600
    assert dir_fd >= 0
    assert not inheritable
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("mutation", ("symlink", "fifo"))
def test_fileio_recovery_marker_opener_rejects_hostile_names_without_blocking(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    governed_model_case.crash_install_at(  # type: ignore[attr-defined]
        "after_publish_before_seal"
    )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    if mutation == "symlink":
        target = marker_path.with_name(".attacker-marker-target")
        target.write_bytes(b"")
        target.chmod(0o600)
        marker_path.symlink_to(target.name)
    elif mutation == "fifo":
        os.mkfifo(marker_path, mode=0o600)
    else:  # pragma: no cover - closed parametrization
        raise AssertionError(f"unknown hostile marker mutation: {mutation}")
    real_open = os.open
    marker_open_attempts = 0

    def track_marker_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal marker_open_attempts
        if path == marker_path.name and dir_fd is not None:
            marker_open_attempts += 1
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", track_marker_open)

    started = time.monotonic()
    with pytest.raises(PermissionError):
        governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )

    assert time.monotonic() - started < 2
    assert marker_open_attempts == 0
    assert governed_model_case.final_revision_mode == 0o700  # type: ignore[attr-defined]
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


def test_non_linux_non_darwin_platform_rejects_renameat2_even_when_exported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    parent_slot = fs_module._OwnedDirectoryOwnerSlot()
    OwnedDirectory.open(tmp_path, parent_slot)
    parent = parent_slot.owner
    assert parent is not None
    renameat2_called = False

    class RenameAt2OnlyLibc:
        def renameat2(self, *_args: object) -> int:
            nonlocal renameat2_called
            renameat2_called = True
            return 0

    monkeypatch.setattr(fs_module.sys, "platform", "freebsd14")
    monkeypatch.setattr(
        fs_module.ctypes,
        "CDLL",
        lambda *_args, **_kwargs: RenameAt2OnlyLibc(),
    )
    try:
        with pytest.raises(OSError) as caught:
            fs_module.atomic_publish_dir_noreplace(parent, "source", "target")
    finally:
        parent.close()

    assert caught.value.errno == errno.ENOTSUP
    assert not renameat2_called


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
@pytest.mark.parametrize(
    "precommit_fault",
    (
        "prepared_mode",
        "prepared_fsync",
        "prepared_parent_fsync",
        "prepared_validation",
        "atomic_rename",
    ),
)
def test_precommit_marker_fault_stays_authoritative_when_mode_rollback_fails(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    precommit_fault: str,
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
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    primary = OSError(f"scripted prepared marker {precommit_fault} failure")
    rollback_error = OSError("scripted prepared marker rollback failure")
    fault_injected = False
    faults_active = True
    rollback_attempts = 0
    marker_close_attempts = 0
    real_fchmod = os.fchmod
    real_fsync = os.fsync
    owner_type = installer_module._PublicationMarkerOwner
    real_owner_close = owner_type.close
    real_chmod = OwnedDirectory.chmod
    real_directory_fsync = OwnedDirectory.fsync
    real_require_marker = ModelInstaller._require_recovery_marker
    real_atomic_publish = installer_module.atomic_publish_dir_noreplace

    def marker_matches_descriptor(descriptor: int) -> bool:
        try:
            marker = marker_path.stat(follow_symlinks=False)
            identity = os.fstat(descriptor)
        except (FileNotFoundError, OSError):
            return False
        return (identity.st_dev, identity.st_ino) == (marker.st_dev, marker.st_ino)

    def revision_matches(directory: OwnedDirectory) -> bool:
        try:
            revision = revision_path.stat(follow_symlinks=False)
        except FileNotFoundError:
            return False
        return (directory.identity.device, directory.identity.inode) == (
            revision.st_dev,
            revision.st_ino,
        )

    def fail_prepared_mode(descriptor: int, mode: int) -> None:
        nonlocal fault_injected
        target = (
            faults_active
            and precommit_fault == "prepared_mode"
            and mode == 0o400
            and marker_matches_descriptor(descriptor)
            and not fault_injected
        )
        real_fchmod(descriptor, mode)
        if target:
            fault_injected = True
            raise primary

    def fail_prepared_fsync(descriptor: int) -> None:
        nonlocal fault_injected
        target = (
            faults_active
            and precommit_fault == "prepared_fsync"
            and marker_matches_descriptor(descriptor)
            and stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o400
            and not fault_injected
        )
        real_fsync(descriptor)
        if target:
            fault_injected = True
            raise primary

    def fail_prepared_validation(
        model: OwnedDirectory,
        revision: str,
        descriptor: int,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal fault_injected
        real_require_marker(model, revision, descriptor, *args, **kwargs)
        if (
            faults_active
            and precommit_fault == "prepared_validation"
            and marker_matches_descriptor(descriptor)
            and stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o400
            and not fault_injected
        ):
            fault_injected = True
            raise primary

    def fail_prepared_parent_fsync(directory: OwnedDirectory) -> None:
        nonlocal fault_injected
        model = model_path.stat(follow_symlinks=False)
        target = (
            faults_active
            and precommit_fault == "prepared_parent_fsync"
            and marker_path.exists()
            and stat.S_IMODE(marker_path.stat(follow_symlinks=False).st_mode) == 0o400
            and (directory.identity.device, directory.identity.inode)
            == (model.st_dev, model.st_ino)
            and not fault_injected
        )
        real_directory_fsync(directory)
        if target:
            fault_injected = True
            raise primary

    def track_precommit_marker_close(owner: object) -> None:
        nonlocal marker_close_attempts
        if not owner.closed:  # type: ignore[attr-defined]
            descriptor = owner.fileno()  # type: ignore[attr-defined]
            if marker_matches_descriptor(descriptor):
                marker_close_attempts += 1
        real_owner_close(owner)  # type: ignore[arg-type]

    def fail_atomic_marker_publish(
        parent: OwnedDirectory,
        source: str,
        target: str,
        **kwargs: object,
    ) -> None:
        nonlocal fault_injected
        if (
            faults_active
            and precommit_fault == "atomic_rename"
            and source == marker_path.name
            and target == proof_path.name
            and not fault_injected
        ):
            fault_injected = True
            raise primary
        real_atomic_publish(parent, source, target, **kwargs)  # type: ignore[arg-type]

    def fail_mode_rollback(directory: OwnedDirectory, mode: int) -> None:
        nonlocal rollback_attempts
        if faults_active and fault_injected and mode == 0o700 and revision_matches(directory):
            rollback_attempts += 1
            raise rollback_error
        real_chmod(directory, mode)

    monkeypatch.setattr(os, "fchmod", fail_prepared_mode)
    monkeypatch.setattr(os, "fsync", fail_prepared_fsync)
    monkeypatch.setattr(owner_type, "close", track_precommit_marker_close)
    monkeypatch.setattr(
        ModelInstaller,
        "_require_recovery_marker",
        staticmethod(fail_prepared_validation),
    )
    monkeypatch.setattr(OwnedDirectory, "fsync", fail_prepared_parent_fsync)
    monkeypatch.setattr(
        installer_module,
        "atomic_publish_dir_noreplace",
        fail_atomic_marker_publish,
    )
    monkeypatch.setattr(OwnedDirectory, "chmod", fail_mode_rollback)

    caught: BaseException | None = None
    try:
        unexpected = governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
    except BaseException as error:
        caught = error
    else:
        unexpected.close()

    assert caught is primary
    assert fault_injected
    assert rollback_attempts == 1
    assert getattr(primary, "__notes__", []) == ["additional recovery rollback failure"]
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    assert marker_path.exists()
    assert stat.S_IMODE(marker_path.stat(follow_symlinks=False).st_mode) == 0o400
    assert not proof_path.exists()
    assert marker_close_attempts == 1
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

    def probe_activation() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
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

    denied = probe_activation()
    assert denied.returncode == 0, denied.stderr

    faults_active = False
    recovered = governed_model_case._installer().install(  # type: ignore[attr-defined]
        governed_model_case.model_id  # type: ignore[attr-defined]
    )
    recovered.close()

    assert not marker_path.exists()
    assert stat.S_IMODE(proof_path.stat(follow_symlinks=False).st_mode) == 0o400
    available = probe_activation()
    assert available.returncode == 1, available.stderr
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
def test_atomic_marker_publish_collision_keeps_marker_until_retry(
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
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    collision_injected = False
    faults_active = True
    rollback_attempts = 0
    real_atomic_publish = installer_module.atomic_publish_dir_noreplace
    real_chmod = OwnedDirectory.chmod

    def revision_matches(directory: OwnedDirectory) -> bool:
        try:
            revision = revision_path.stat(follow_symlinks=False)
        except FileNotFoundError:
            return False
        return (directory.identity.device, directory.identity.inode) == (
            revision.st_dev,
            revision.st_ino,
        )

    def collide_with_marker_publish(
        parent: OwnedDirectory,
        source: str,
        target: str,
        **kwargs: object,
    ) -> None:
        nonlocal collision_injected
        if (
            faults_active
            and source == marker_path.name
            and target == proof_path.name
            and not collision_injected
        ):
            proof_path.write_bytes(b"")
            proof_path.chmod(0o400)
            collision_injected = True
        real_atomic_publish(parent, source, target, **kwargs)  # type: ignore[arg-type]

    def fail_mode_rollback(directory: OwnedDirectory, mode: int) -> None:
        nonlocal rollback_attempts
        if faults_active and collision_injected and mode == 0o700 and revision_matches(directory):
            rollback_attempts += 1
            raise OSError("scripted collision rollback failure")
        real_chmod(directory, mode)

    monkeypatch.setattr(
        installer_module,
        "atomic_publish_dir_noreplace",
        collide_with_marker_publish,
    )
    monkeypatch.setattr(OwnedDirectory, "chmod", fail_mode_rollback)

    caught: BaseException | None = None
    try:
        unexpected = governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
    except BaseException as error:
        caught = error
    else:
        unexpected.close()

    assert isinstance(caught, FileExistsError)
    assert collision_injected
    assert rollback_attempts == 1
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    assert marker_path.exists()
    assert stat.S_IMODE(marker_path.stat(follow_symlinks=False).st_mode) == 0o400
    assert proof_path.exists()
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]

    with pytest.raises(RuntimeError, match="model is not installed and verified"):
        ModelRegistry.load(
            governed_model_case.manifest,  # type: ignore[attr-defined]
            model_root=governed_model_case.model_root,  # type: ignore[attr-defined]
        ).activate(governed_model_case.model_id)  # type: ignore[attr-defined]

    faults_active = False
    recovered = governed_model_case._installer().install(  # type: ignore[attr-defined]
        governed_model_case.model_id  # type: ignore[attr-defined]
    )
    recovered.close()
    assert not marker_path.exists()
    assert stat.S_IMODE(proof_path.stat(follow_symlinks=False).st_mode) == 0o400
    assert governed_model_case.final_revision_is_complete_and_verified()  # type: ignore[attr-defined]
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
@pytest.mark.parametrize(
    "namespace_probe_fault",
    (False, True),
    ids=("namespace-readable", "namespace-probe-fault"),
)
def test_proven_atomic_marker_publish_ignores_success_then_error_diagnostic(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    namespace_probe_fault: bool,
) -> None:
    if phase == "recovery":
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
    revision_path = (
        governed_model_case.model_root  # type: ignore[attr-defined]
        / governed_model_case.model_id  # type: ignore[attr-defined]
        / ("a" * 40)
    )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    diagnostic = OSError("scripted post-rename helper diagnostic")
    rollback_error = OSError("scripted post-rename rollback failure")
    diagnostic_injected = False
    probe_fault_active = True
    namespace_probe_attempts = 0
    rollback_attempts = 0
    real_atomic_publish = installer_module.atomic_publish_dir_noreplace
    real_chmod = OwnedDirectory.chmod
    real_stat = os.stat

    def publish_then_report_error(
        parent: OwnedDirectory,
        source: str,
        target: str,
        **kwargs: object,
    ) -> None:
        nonlocal diagnostic_injected
        real_atomic_publish(parent, source, target, **kwargs)  # type: ignore[arg-type]
        if source == marker_path.name and target == proof_path.name and not diagnostic_injected:
            diagnostic_injected = True
            raise diagnostic

    def fail_postcommit_namespace_probe(
        path: object,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal namespace_probe_attempts
        if (
            namespace_probe_fault
            and probe_fault_active
            and diagnostic_injected
            and path == proof_path.name
            and dir_fd is not None
        ):
            namespace_probe_attempts += 1
            raise OSError("scripted committed namespace probe failure")
        return real_stat(  # type: ignore[arg-type]
            path,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )

    def track_forbidden_rollback(directory: OwnedDirectory, mode: int) -> None:
        nonlocal rollback_attempts
        if diagnostic_injected and mode == 0o700 and revision_path.exists():
            revision = revision_path.stat(follow_symlinks=False)
            if (directory.identity.device, directory.identity.inode) == (
                revision.st_dev,
                revision.st_ino,
            ):
                rollback_attempts += 1
                if namespace_probe_fault:
                    raise rollback_error
        real_chmod(directory, mode)

    monkeypatch.setattr(
        installer_module,
        "atomic_publish_dir_noreplace",
        publish_then_report_error,
    )
    monkeypatch.setattr(os, "stat", fail_postcommit_namespace_probe)
    monkeypatch.setattr(OwnedDirectory, "chmod", track_forbidden_rollback)

    activated = governed_model_case._installer().install(  # type: ignore[attr-defined]
        governed_model_case.model_id  # type: ignore[attr-defined]
    )
    probe_fault_active = False
    try:
        assert activated.all_files_verified
    finally:
        activated.close()

    assert diagnostic_injected
    assert namespace_probe_attempts == 0
    assert rollback_attempts == 0
    assert not marker_path.exists()
    assert stat.S_IMODE(proof_path.stat(follow_symlinks=False).st_mode) == 0o400
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    fresh = ModelRegistry.load(
        governed_model_case.manifest,  # type: ignore[attr-defined]
        model_root=governed_model_case.model_root,  # type: ignore[attr-defined]
    ).activate(governed_model_case.model_id)  # type: ignore[attr-defined]
    fresh.close()
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
def test_activation_construction_failure_after_atomic_commit_does_not_roll_back(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    if phase == "recovery":
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
    revision_path = (
        governed_model_case.model_root  # type: ignore[attr-defined]
        / governed_model_case.model_id  # type: ignore[attr-defined]
        / ("a" * 40)
    )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    primary = ModelVerificationError("scripted postcommit activation construction failure")
    rollback_attempts = 0
    close_attempts = 0
    artifact_descriptors: list[int] = []
    real_chmod = OwnedDirectory.chmod
    real_file_close = VerifiedModelFile.close

    def fail_activation_construction(
        _cls: type[ActivatedModel],
        _entry: object,
        files: tuple[VerifiedModelFile, ...],
        _owner_slot: object,
    ) -> None:
        artifact_descriptors.extend(item.fd for item in files)
        raise primary

    def track_forbidden_rollback(directory: OwnedDirectory, mode: int) -> None:
        nonlocal rollback_attempts
        if proof_path.exists() and not marker_path.exists() and mode == 0o700:
            revision = revision_path.stat(follow_symlinks=False)
            if (directory.identity.device, directory.identity.inode) == (
                revision.st_dev,
                revision.st_ino,
            ):
                rollback_attempts += 1
        real_chmod(directory, mode)

    def track_file_close(handle: VerifiedModelFile) -> None:
        nonlocal close_attempts
        if artifact_descriptors and handle.fd in artifact_descriptors:
            close_attempts += 1
        real_file_close(handle)

    monkeypatch.setattr(
        ActivatedModel,
        "from_manifest",
        classmethod(fail_activation_construction),
    )
    monkeypatch.setattr(OwnedDirectory, "chmod", track_forbidden_rollback)
    monkeypatch.setattr(VerifiedModelFile, "close", track_file_close)

    caught: BaseException | None = None
    try:
        governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
    except BaseException as error:
        caught = error

    assert caught is primary
    assert rollback_attempts == 0
    assert close_attempts == 1
    assert len(artifact_descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(artifact_descriptors[0])
    assert not marker_path.exists()
    assert stat.S_IMODE(proof_path.stat(follow_symlinks=False).st_mode) == 0o400
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("phase", ("fresh", "recovery"))
def test_postcommit_directory_close_failure_keeps_marker_inode_authoritative_as_proof(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    if phase == "recovery":
        governed_model_case.crash_install_at(  # type: ignore[attr-defined]
            "after_publish_before_seal"
        )
    revision_path = (
        governed_model_case.model_root  # type: ignore[attr-defined]
        / governed_model_case.model_id  # type: ignore[attr-defined]
        / ("a" * 40)
    )
    marker_path = governed_model_case.recovery_marker_path  # type: ignore[attr-defined]
    proof_path = governed_model_case.publication_commit_path  # type: ignore[attr-defined]
    primary = OSError("scripted postcommit revision close failure")
    marker_identity: tuple[int, int] | None = None
    fault_injected = False
    activation_close_attempts = 0
    artifact_descriptors: list[int] = []
    real_acquire_marker = ModelInstaller._acquire_recovery_marker
    real_directory_close = OwnedDirectory.close
    real_activated_close = ActivatedModel.close
    real_from_manifest = ActivatedModel.from_manifest

    def capture_marker(
        model: OwnedDirectory,
        revision: str,
        owner_slot: installer_module._PublicationMarkerOwnerSlot,
        *,
        create: bool,
    ) -> None:
        nonlocal marker_identity
        real_acquire_marker(
            model,
            revision,
            owner_slot,
            create=create,
        )
        assert owner_slot.owner is not None
        descriptor = owner_slot.owner.fileno()
        identity = os.fstat(descriptor)
        marker_identity = (identity.st_dev, identity.st_ino)

    def capture_activation(
        _cls: type[ActivatedModel],
        entry: object,
        files: tuple[VerifiedModelFile, ...],
        owner_slot: object,
    ) -> None:
        real_from_manifest(entry, files, owner_slot)  # type: ignore[arg-type]
        activated = owner_slot.owner  # type: ignore[attr-defined]
        assert isinstance(activated, ActivatedModel)
        artifact_descriptors.extend(item.fd for item in activated.files)

    def fail_postcommit_revision_close(directory: OwnedDirectory) -> None:
        nonlocal fault_injected
        target = False
        if proof_path.exists() and not marker_path.exists() and revision_path.exists():
            revision = revision_path.stat(follow_symlinks=False)
            target = (directory.identity.device, directory.identity.inode) == (
                revision.st_dev,
                revision.st_ino,
            ) and not fault_injected
        real_directory_close(directory)
        if target:
            fault_injected = True
            raise primary

    def track_activation_close(activated: ActivatedModel) -> None:
        nonlocal activation_close_attempts
        activation_close_attempts += 1
        real_activated_close(activated)

    monkeypatch.setattr(
        ModelInstaller,
        "_acquire_recovery_marker",
        staticmethod(capture_marker),
    )
    monkeypatch.setattr(
        ActivatedModel,
        "from_manifest",
        classmethod(capture_activation),
    )
    monkeypatch.setattr(OwnedDirectory, "close", fail_postcommit_revision_close)
    monkeypatch.setattr(ActivatedModel, "close", track_activation_close)

    caught: BaseException | None = None
    try:
        unexpected = governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
    except BaseException as error:
        caught = error
    else:
        unexpected.close()

    assert caught is primary
    assert fault_injected
    assert activation_close_attempts == 1
    assert len(artifact_descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(artifact_descriptors[0])
    assert marker_identity is not None
    proof = proof_path.stat(follow_symlinks=False)
    assert (proof.st_dev, proof.st_ino) == marker_identity
    assert not marker_path.exists()
    assert governed_model_case.final_revision_mode == 0o500  # type: ignore[attr-defined]
    assert governed_model_case.final_revision_is_complete_and_verified()  # type: ignore[attr-defined]
    assert governed_model_case.open_descriptor_count == 0  # type: ignore[attr-defined]


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
        _cls: type[VerifiedModelFile],
        _item: object,
        descriptor_slot: object,
        _owner_slot: object,
    ) -> None:
        retained_descriptor.append(_owned_descriptor(descriptor_slot))
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
        _cls: type[VerifiedModelFile],
        item: object,
        descriptor_slot: object,
        owner_slot: object,
    ) -> None:
        real_from_manifest(item, descriptor_slot, owner_slot)  # type: ignore[arg-type]
        handle = owner_slot.owner  # type: ignore[attr-defined]
        assert isinstance(handle, VerifiedModelFile)
        retained_handle.append(handle)

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


def test_committed_reuse_tail_close_preserves_primary_oserror(
    governed_model_case: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed = governed_model_case.install()  # type: ignore[attr-defined]
    installed.close()
    revision_path = (
        governed_model_case.model_root  # type: ignore[attr-defined]
        / governed_model_case.model_id  # type: ignore[attr-defined]
        / ("a" * 40)
    )
    revision_metadata = revision_path.stat(follow_symlinks=False)
    revision_identity = (revision_metadata.st_dev, revision_metadata.st_ino)
    primary = OSError("scripted committed-reuse tail close failure")
    revision_close_attempts = 0
    real_close = OwnedDirectory.close

    def fail_second_revision_close(directory: OwnedDirectory) -> None:
        nonlocal revision_close_attempts
        identity = (directory.identity.device, directory.identity.inode)
        if identity == revision_identity:
            try:
                os.fstat(directory.fd)
            except OSError as error:
                assert error.errno == errno.EBADF
                real_close(directory)
                return
            revision_close_attempts += 1
            real_close(directory)
            if revision_close_attempts == 2:
                raise primary
            return
        real_close(directory)

    monkeypatch.setattr(OwnedDirectory, "close", fail_second_revision_close)

    caught: BaseException | None = None
    try:
        unexpected = governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )
    except BaseException as error:
        caught = error
    else:
        unexpected.close()

    assert caught is primary
    assert revision_close_attempts == 2
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

    assert governed_model_case.final_revision_mode == 0o700  # type: ignore[attr-defined]
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


def test_successful_recovery_promotes_prepared_marker_atomically_after_verify(
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
    proof_path = model_path / f".publication-verified-{'a' * 40}"
    model_metadata = model_path.stat(follow_symlinks=False)
    revision_metadata = revision_path.stat(follow_symlinks=False)
    model_identity = (model_metadata.st_dev, model_metadata.st_ino)
    revision_identity = (revision_metadata.st_dev, revision_metadata.st_ino)
    events: list[str] = []
    real_fsync = os.fsync
    real_chmod = OwnedDirectory.chmod
    real_hash = installer_module.hash_exact_fd
    real_atomic_publish = installer_module.atomic_publish_dir_noreplace

    def track_fsync(descriptor: int) -> None:
        identity = os.fstat(descriptor)
        descriptor_identity = (identity.st_dev, identity.st_ino)
        if marker_path.exists():
            marker = marker_path.stat(follow_symlinks=False)
            if descriptor_identity == (marker.st_dev, marker.st_ino):
                events.append(f"marker_fsync_{stat.S_IMODE(identity.st_mode):03o}")
            elif descriptor_identity == model_identity:
                events.append("model_fsync")
            elif descriptor_identity == revision_identity:
                events.append("revision_fsync")
        elif descriptor_identity == model_identity:
            events.append("model_fsync")
        elif descriptor_identity == revision_identity:
            events.append("revision_fsync")
        real_fsync(descriptor)

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

    def track_atomic_publish(
        parent: OwnedDirectory,
        source: str,
        target: str,
        **kwargs: object,
    ) -> None:
        real_atomic_publish(parent, source, target, **kwargs)  # type: ignore[arg-type]
        if source == marker_path.name and target == proof_path.name:
            events.append("marker_to_proof")

    monkeypatch.setattr(os, "fsync", track_fsync)
    monkeypatch.setattr(OwnedDirectory, "chmod", track_chmod)
    monkeypatch.setattr(installer_module, "hash_exact_fd", track_hash)
    monkeypatch.setattr(
        installer_module,
        "atomic_publish_dir_noreplace",
        track_atomic_publish,
    )

    governed_model_case.restart_and_reconcile()  # type: ignore[attr-defined]

    marker_fsync = events.index("marker_fsync_600")
    assert events[marker_fsync:] == [
        "marker_fsync_600",
        "model_fsync",
        "seal",
        "revision_fsync",
        "post_seal_hash",
        "revision_fsync",
        "model_fsync",
        "marker_fsync_400",
        "model_fsync",
        "marker_to_proof",
    ]
    assert not governed_model_case.recovery_marker_exists  # type: ignore[attr-defined]


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
    owner_type = installer_module._PublicationMarkerOwner
    real_owner_close = owner_type.close

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

    def track_marker_close(owner: object) -> None:
        nonlocal close_fault_injected
        descriptor = None if owner.closed else owner.fileno()  # type: ignore[attr-defined]
        target = descriptor in marker_descriptors
        if target and descriptor is not None:
            marker_close_attempts.append(descriptor)
        real_owner_close(owner)  # type: ignore[arg-type]
        if target and not close_fault_injected:
            close_fault_injected = True
            raise secondary

    monkeypatch.setattr(os, "fsync", fail_durability_fsync)
    monkeypatch.setattr(owner_type, "close", track_marker_close)

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
    owner_type = installer_module._PublicationMarkerOwner
    real_owner_close = owner_type.close

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

    def track_marker_close(owner: object) -> None:
        nonlocal marker_close_attempts
        descriptor = owner.fileno()  # type: ignore[attr-defined]
        identity = os.fstat(descriptor)
        if (identity.st_dev, identity.st_ino) == marker_identity:
            marker_close_attempts += 1
        real_owner_close(owner)  # type: ignore[arg-type]

    monkeypatch.setattr(OwnedDirectory, "fsync", mutate_marker_after_durability_fsync)
    monkeypatch.setattr(OwnedDirectory, "chmod", track_seal)
    monkeypatch.setattr(owner_type, "close", track_marker_close)

    with pytest.raises(PermissionError) as caught:
        governed_model_case._installer().install(  # type: ignore[attr-defined]
            governed_model_case.model_id  # type: ignore[attr-defined]
        )

    assert isinstance(caught.value.__cause__, (FileNotFoundError, PermissionError))
    assert marker_mutated
    assert seal_attempts == 0
    assert marker_close_attempts == 1
    assert governed_model_case.final_revision_mode == initial_mode  # type: ignore[attr-defined]
    expected_notes = (
        ["additional publication commit resolution failure"] if initial_mode == 0o500 else []
    )
    assert getattr(caught.value.__cause__, "__notes__", []) == expected_notes
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
