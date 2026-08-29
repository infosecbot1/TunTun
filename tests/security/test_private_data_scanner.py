import dataclasses
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

import scripts.verify_private_data as private_data_scanner
from scripts import scan_private_data as private_data_cli
from scripts.verify_private_data import scan


def _credential(fill: bytes = b"A") -> bytes:
    return b"".join((b"sk-", b"proj-", fill * 24))


def _private_key_marker() -> bytes:
    return b"".join((b"-----BEGIN ", b"PRIVATE ", b"KEY-----"))


def _git(root: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    return subprocess.run(
        ("git", "-C", str(root), *arguments),
        input=input_bytes,
        capture_output=True,
        check=True,
    ).stdout


def _source_repository(root: Path) -> Path:
    _git(root, "init", "-q")
    return root


def test_scanner_rejects_secret_and_database(tmp_path: Path) -> None:
    credential = _credential().decode("ascii")
    (tmp_path / "leak.txt").write_text(credential, encoding="utf-8")
    (tmp_path / "family.sqlite3").write_bytes(b"SQLite format 3\x00")
    assert {(finding.path.name, finding.reason) for finding in scan(tmp_path)} == {
        ("family.sqlite3", "forbidden-extension"),
        ("leak.txt", "credential-pattern"),
    }


def test_scanner_allows_declared_synthetic_text(tmp_path: Path) -> None:
    fixture = tmp_path / "tests" / "fixtures" / "synthetic"
    fixture.mkdir(parents=True)
    (fixture / "case.json").write_text('{"speaker":"synthetic-guest"}', encoding="utf-8")
    assert scan(tmp_path) == ()


def test_source_root_omits_git_ignored_tool_cache_and_pnpm_outputs(
    tmp_path: Path,
) -> None:
    root = _source_repository(tmp_path)
    (root / ".gitignore").write_text(
        "__pycache__/\n.mypy_cache/\nnode_modules/\ndist/\nvar/\n",
        encoding="utf-8",
    )
    _git(root, "add", ".gitignore")
    (root / ".mypy_cache").mkdir()
    (root / ".mypy_cache" / "cache.db").write_bytes(b"SQLite format 3\x00")
    (root / "pkg" / "__pycache__").mkdir(parents=True)
    (root / "pkg" / "__pycache__" / "compiled.pyc").write_bytes(_credential())
    pnpm = root / "apps" / "admin" / "node_modules"
    (pnpm / ".pnpm" / "synthetic").mkdir(parents=True)
    (pnpm / "synthetic").symlink_to(".pnpm/synthetic", target_is_directory=True)
    assert scan(root) == ()


def test_nonignored_source_subtree_uses_git_inventory(tmp_path: Path) -> None:
    root = _source_repository(tmp_path)
    (root / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
    source = root / "src"
    source.mkdir()
    (source / "tracked.py").write_text("VALUE = 'synthetic'\n", encoding="utf-8")
    _git(root, "add", ".gitignore", "src/tracked.py")
    ignored = source / "__pycache__" / "tracked.pyc"
    ignored.parent.mkdir()
    ignored.write_bytes(_credential())
    assert scan(source) == ()


def test_visible_untracked_source_file_is_scanned(tmp_path: Path) -> None:
    root = _source_repository(tmp_path)
    leak = root / "visible-untracked.txt"
    leak.write_bytes(_credential())
    assert any(
        finding.path == Path("visible-untracked.txt") and finding.reason == "credential-pattern"
        for finding in scan(root)
    )


def test_staged_index_blob_is_scanned_even_when_worktree_copy_is_clean(
    tmp_path: Path,
) -> None:
    root = _source_repository(tmp_path)
    staged = root / "staged-only.txt"
    staged.write_bytes(_credential())
    _git(root, "add", "staged-only.txt")
    staged.write_text("synthetic working tree\n", encoding="utf-8")
    assert any(
        finding.path == Path("<git-index>/staged-only.txt")
        and finding.reason == "credential-pattern"
        for finding in scan(root)
    )


def test_force_tracked_file_beneath_ignored_directory_is_scanned(
    tmp_path: Path,
) -> None:
    root = _source_repository(tmp_path)
    (root / ".gitignore").write_text("dist/\n", encoding="utf-8")
    leak = root / "dist" / "tracked.txt"
    leak.parent.mkdir()
    leak.write_bytes(_credential())
    _git(root, "add", ".gitignore")
    _git(root, "add", "-f", "dist/tracked.txt")
    assert any(item.reason == "credential-pattern" for item in scan(root))


def test_explicit_ignored_artifact_root_receives_complete_physical_scan(
    tmp_path: Path,
) -> None:
    root = _source_repository(tmp_path)
    (root / ".gitignore").write_text("dist/\n", encoding="utf-8")
    _git(root, "add", ".gitignore")
    artifact = root / "dist"
    artifact.mkdir()
    (artifact / "candidate.txt").write_bytes(_credential())
    assert scan(root) == ()
    assert any(item.reason == "credential-pattern" for item in scan(artifact))


def test_conflicted_git_index_blocks_source_attestation(tmp_path: Path) -> None:
    root = _source_repository(tmp_path)
    ours = _git(root, "hash-object", "-w", "--stdin", input_bytes=b"ours\n").strip()
    theirs = _git(root, "hash-object", "-w", "--stdin", input_bytes=b"theirs\n").strip()
    _git(
        root,
        "update-index",
        "--index-info",
        input_bytes=b"".join(
            (
                b"100644 ",
                ours,
                b" 2\tconflict.txt\n",
                b"100644 ",
                theirs,
                b" 3\tconflict.txt\n",
            )
        ),
    )
    assert scan(root)[0].reason == "git-index-conflict"
    receipt = private_data_cli.evaluate(["--paths", str(root)])
    assert receipt.complete is False
    assert private_data_cli.main(["--paths", str(root)]) == 2


@pytest.mark.parametrize(
    "reason",
    ("git-inventory-failed", "git-inventory-timeout"),
)
def test_failed_or_timed_out_git_inventory_blocks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
) -> None:
    root = _source_repository(tmp_path)

    def fail(*_args, **_kwargs):
        raise private_data_scanner.GitInventoryError(root, reason)

    monkeypatch.setattr(private_data_scanner, "_git_output", fail)
    assert scan(root)[0].reason == reason


def test_malformed_git_inventory_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _source_repository(tmp_path)
    original = private_data_scanner._git_output

    def malformed(repository, arguments, *, max_bytes):
        if tuple(arguments[:2]) == ("ls-files", "--stage"):
            return b"not-an-index-record\0"
        return original(repository, arguments, max_bytes=max_bytes)

    monkeypatch.setattr(private_data_scanner, "_git_output", malformed)
    assert scan(root)[0].reason == "git-inventory-malformed"


def test_git_inventory_drift_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _source_repository(tmp_path)
    tracked = root / "tracked.txt"
    tracked.write_text("synthetic\n", encoding="utf-8")
    _git(root, "add", "tracked.txt")
    original = private_data_scanner._capture_source_snapshot
    calls = 0

    def drift(repository, scope):
        nonlocal calls
        calls += 1
        snapshot = original(repository, scope)
        if calls == 2:
            return dataclasses.replace(snapshot, index_raw=snapshot.index_raw + b"\0")
        return snapshot

    monkeypatch.setattr(private_data_scanner, "_capture_source_snapshot", drift)
    assert any(item.reason == "source-inventory-drift" for item in scan(root))


def test_symlink_ancestor_cannot_swap_the_classified_repository(tmp_path: Path) -> None:
    dirty = tmp_path / "dirty"
    clean = tmp_path / "clean"
    dirty.mkdir()
    clean.mkdir()
    _source_repository(dirty)
    _source_repository(clean)
    (dirty / "secret.txt").write_bytes(_credential())
    (clean / "secret.txt").write_text("synthetic\n", encoding="utf-8")
    _git(dirty, "add", "secret.txt")
    _git(clean, "add", "secret.txt")
    entry = tmp_path / "selected"
    entry.symlink_to(dirty, target_is_directory=True)
    findings = scan(entry / "secret.txt")
    assert findings == (private_data_scanner.Finding(entry, "filesystem-symlink-ancestor"),)


def test_opened_working_candidate_must_match_snapshot_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _source_repository(tmp_path)
    candidate = root / "visible.txt"
    replacement = root / "replacement.txt"
    candidate.write_bytes(_credential())
    replacement.write_text("synthetic\n", encoding="utf-8")
    original = private_data_scanner._open_relative_candidate
    swapped = False

    def replace_before_open(root_fd, repository, relative, expected_identity):
        nonlocal swapped
        if not swapped and relative == Path("visible.txt"):
            swapped = True
            candidate.replace(root / "old-visible.txt")
            replacement.replace(candidate)
        yield from original(root_fd, repository, relative, expected_identity)

    monkeypatch.setattr(
        private_data_scanner,
        "_open_relative_candidate",
        replace_before_open,
    )
    assert any(item.reason == "input-changed-during-scan" for item in scan(root))


@pytest.mark.parametrize("kind", ("fifo", "socket"))
def test_unignored_special_entry_missing_from_git_inventory_blocks(
    tmp_path: Path,
    kind: str,
) -> None:
    root = _source_repository(tmp_path)
    special = root / f"visible-{kind}"
    listener = None
    if kind == "fifo":
        os.mkfifo(special)
    else:
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(special))
    try:
        assert any(
            item.path == special and item.reason == "filesystem-special" for item in scan(root)
        )
    finally:
        if listener is not None:
            listener.close()


def test_explicit_out_root_with_ignored_child_is_artifact_scanned(tmp_path: Path) -> None:
    root = _source_repository(tmp_path)
    (root / ".gitignore").write_text("out/*\n", encoding="utf-8")
    _git(root, "add", ".gitignore")
    output = root / "out"
    output.mkdir()
    (output / "hidden.txt").write_bytes(_credential())
    assert any(item.reason == "credential-pattern" for item in scan(output))


@pytest.mark.parametrize("exclude_source", ("info", "local", "global", "system"))
def test_ambient_git_excludes_cannot_hide_source_candidates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exclude_source: str,
) -> None:
    root = _source_repository(tmp_path)
    hidden = root / "hidden.txt"
    hidden.write_bytes(_credential())
    if exclude_source == "info":
        (root / ".git" / "info" / "exclude").write_text("hidden.txt\n", encoding="utf-8")
    elif exclude_source == "local":
        exclude = tmp_path / "local-excludes"
        exclude.write_text("hidden.txt\n", encoding="utf-8")
        _git(root, "config", "core.excludesFile", str(exclude))
    else:
        config = tmp_path / f"{exclude_source}.gitconfig"
        exclude = tmp_path / f"{exclude_source}-excludes"
        exclude.write_text("hidden.txt\n", encoding="utf-8")
        config.write_text(
            f"[core]\n\texcludesFile = {exclude}\n",
            encoding="utf-8",
        )
        monkeypatch.setenv(f"GIT_CONFIG_{exclude_source.upper()}", str(config))
    assert any(item.reason == "credential-pattern" for item in scan(root))


def test_git_processes_disable_lazy_fetch_prompts_configs_and_proxies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _source_repository(tmp_path)
    tracked = root / "tracked.txt"
    tracked.write_text("synthetic\n", encoding="utf-8")
    _git(root, "add", "tracked.txt")
    observed = []
    original = private_data_scanner.subprocess.Popen

    def recording_popen(*args, **kwargs):
        observed.append((args[0], dict(kwargs["env"]), kwargs.get("pass_fds", ())))
        return original(*args, **kwargs)

    monkeypatch.setattr(private_data_scanner.subprocess, "Popen", recording_popen)
    assert scan(root) == ()
    assert observed
    for argv, environment, pass_fds in observed:
        assert argv[:5] == (
            sys.executable,
            "-I",
            "-S",
            "-c",
            private_data_scanner.GIT_FD_EXEC_HELPER,
        )
        assert argv[5].isascii() and argv[5].isdigit()
        assert argv[6] == private_data_scanner.GIT_EXECUTABLE
        git_arguments = argv[6:]
        assert "-C" not in git_arguments
        assert "--git-dir=.git" in git_arguments
        assert "--work-tree=." in git_arguments
        for override in (
            "core.excludesFile=/dev/null",
            "core.fsmonitor=false",
            "core.hooksPath=/dev/null",
            "core.untrackedCache=false",
            "maintenance.auto=false",
            "gc.auto=0",
        ):
            assert override in git_arguments
        assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
        assert environment["GIT_CONFIG_GLOBAL"] == "/dev/null"
        assert environment["GIT_CONFIG_SYSTEM"] == "/dev/null"
        assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
        assert environment["GIT_NO_LAZY_FETCH"] == "1"
        assert environment["GIT_OPTIONAL_LOCKS"] == "0"
        assert environment["GIT_ATTR_NOSYSTEM"] == "1"
        assert environment["GIT_TERMINAL_PROMPT"] == "0"
        assert environment["GCM_INTERACTIVE"] == "never"
        assert environment["http_proxy"] == environment["https_proxy"] == ""
        assert pass_fds == (int(argv[5]),)


def test_missing_promised_blob_blocks_without_lazy_fetch(tmp_path: Path) -> None:
    root = _source_repository(tmp_path)
    missing_oid = "f" * 40
    _git(root, "config", "extensions.partialClone", "origin")
    _git(root, "config", "remote.origin.promisor", "true")
    _git(root, "config", "remote.origin.url", "https://127.0.0.1:9/unreachable")
    _git(
        root,
        "update-index",
        "--add",
        "--info-only",
        "--cacheinfo",
        f"100644,{missing_oid},promised.txt",
    )
    assert scan(root) == (
        private_data_scanner.Finding(
            Path("<git-index>/promised.txt"),
            "git-batch-object-missing",
        ),
    )
    assert private_data_cli.evaluate(["--paths", str(root)]).complete is False
    assert private_data_cli.main(["--paths", str(root)]) == 2


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin descriptor launch contract")
def test_darwin_git_startup_never_uses_swappable_lexical_worktree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected_slot = tmp_path / "selected"
    clean_slot = tmp_path / "clean"
    dirty = selected_slot / "repo"
    clean = clean_slot / "repo"
    dirty.mkdir(parents=True)
    clean.mkdir(parents=True)
    _source_repository(dirty)
    _source_repository(clean)
    (dirty / ".gitignore").write_text("ordinary-cache/*\n", encoding="utf-8")
    (dirty / "private.txt").write_bytes(_credential(b"D"))
    (clean / ".gitignore").write_text("private.txt\n", encoding="utf-8")
    (clean / "private.txt").write_text("synthetic\n", encoding="utf-8")

    original_popen = private_data_scanner.subprocess.Popen
    parked_dirty = tmp_path / "parked-dirty"
    swaps = 0

    class RestoringProcess:
        def __init__(self, process):
            self.process = process
            self.restored = False

        def restore(self) -> None:
            if self.restored:
                return
            selected_slot.rename(clean_slot)
            parked_dirty.rename(selected_slot)
            self.restored = True

        def wait(self, *args, **kwargs):
            try:
                return self.process.wait(*args, **kwargs)
            finally:
                self.restore()

        def poll(self):
            return self.process.poll()

        def kill(self):
            return self.process.kill()

        def __getattr__(self, name):
            return getattr(self.process, name)

    def swap_for_lexical_git(arguments, *args, **kwargs):
        nonlocal swaps
        vector = tuple(os.fspath(item) for item in arguments)
        lexical_git = (
            len(vector) >= 5
            and vector[0] == "git"
            and "-C" in vector
            and vector[vector.index("-C") + 1] == str(dirty)
        )
        descriptor_helper = (
            len(vector) >= 8
            and vector[:4] == (sys.executable, "-I", "-S", "-c")
            and vector[4]
            == getattr(
                private_data_scanner,
                "GIT_FD_EXEC_HELPER",
                "not-present",
            )
            and "--git-dir=.git" in vector
        )
        if not (lexical_git or descriptor_helper):
            return original_popen(arguments, *args, **kwargs)
        swaps += 1
        selected_slot.rename(parked_dirty)
        clean_slot.rename(selected_slot)
        try:
            return RestoringProcess(original_popen(arguments, *args, **kwargs))
        except BaseException:
            selected_slot.rename(clean_slot)
            parked_dirty.rename(selected_slot)
            raise

    monkeypatch.setattr(private_data_scanner.subprocess, "Popen", swap_for_lexical_git)
    findings = scan(dirty)
    assert swaps > 0
    assert any(item.reason == "credential-pattern" for item in findings)


def test_replacement_ref_cannot_replace_index_blob_bytes(tmp_path: Path) -> None:
    root = _source_repository(tmp_path)
    payload = root / "payload.txt"
    payload.write_bytes(_credential(b"R"))
    _git(root, "add", "payload.txt")
    indexed_oid = _git(root, "rev-parse", ":payload.txt").strip().decode("ascii")
    clean_oid = (
        _git(
            root,
            "hash-object",
            "-w",
            "--stdin",
            input_bytes=b"ordinary\n",
        )
        .strip()
        .decode("ascii")
    )
    _git(root, "replace", indexed_oid, clean_oid)
    payload.write_text("ordinary\n", encoding="utf-8")
    assert any(item.reason == "credential-pattern" for item in scan(root))


def test_alternate_object_body_must_match_index_oid(tmp_path: Path) -> None:
    import zlib

    root = _source_repository(tmp_path)
    payload = root / "payload.txt"
    payload.write_bytes(_credential(b"A"))
    _git(root, "add", "payload.txt")
    indexed_oid = _git(root, "rev-parse", ":payload.txt").strip().decode("ascii")
    original = root / ".git" / "objects" / indexed_oid[:2] / indexed_oid[2:]
    alternate = tmp_path / "alternate-objects"
    forged = alternate / indexed_oid[:2] / indexed_oid[2:]
    forged.parent.mkdir(parents=True)
    clean = b"ordinary\n"
    forged.write_bytes(zlib.compress(b"blob 9\0" + clean))
    (root / ".git" / "objects" / "info" / "alternates").write_text(
        str(alternate) + "\n",
        encoding="utf-8",
    )
    original.unlink()
    payload.write_bytes(clean)
    assert scan(root) == (
        private_data_scanner.Finding(
            Path("<git-index>/payload.txt"),
            "git-batch-content-oid-mismatch",
        ),
    )


def test_repository_fsmonitor_helper_is_never_invoked(tmp_path: Path) -> None:
    root = _source_repository(tmp_path)
    (root / "ordinary.txt").write_text("ordinary\n", encoding="utf-8")
    _git(root, "add", "ordinary.txt")
    marker = tmp_path / "fsmonitor-was-run"
    hook = tmp_path / "fsmonitor-hook.sh"
    hook.write_text(
        f"#!/bin/sh\n/usr/bin/touch {marker}\nprintf 'token\\n'\n",
        encoding="utf-8",
    )
    hook.chmod(0o700)
    _git(root, "config", "core.fsmonitor", str(hook))
    assert scan(root) == ()
    assert not marker.exists()


def test_history_mode_uses_descriptor_bound_git_and_closed_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _source_repository(tmp_path)
    _git(root, "hash-object", "-w", "--stdin", input_bytes=b"synthetic history\n")
    observed = []
    original = private_data_scanner.subprocess.Popen

    def recording_popen(*args, **kwargs):
        vector = tuple(os.fspath(item) for item in args[0])
        if "--batch-all-objects" in vector:
            observed.append((vector, dict(kwargs["env"]), kwargs.get("pass_fds", ())))
        return original(*args, **kwargs)

    monkeypatch.setattr(private_data_scanner.subprocess, "Popen", recording_popen)
    receipt = private_data_cli.evaluate(
        ["--paths", str(root), "--include-git-history"],
    )
    assert receipt.exit_code() == 0
    assert len(observed) == 1
    argv, environment, pass_fds = observed[0]
    assert argv[:5] == (
        sys.executable,
        "-I",
        "-S",
        "-c",
        private_data_scanner.GIT_FD_EXEC_HELPER,
    )
    assert "-C" not in argv
    assert argv[6] == private_data_scanner.GIT_EXECUTABLE
    assert environment["GIT_NO_LAZY_FETCH"] == "1"
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert environment["http_proxy"] == environment["https_proxy"] == ""
    assert pass_fds == (int(argv[5]),)


def test_history_mode_scans_compressed_archive_objects_with_the_shared_engine(
    tmp_path: Path,
) -> None:
    import io
    import zipfile

    root = _source_repository(tmp_path)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr("nested/config.txt", _credential(b"H"))
    _git(root, "hash-object", "-w", "--stdin", input_bytes=archive.getvalue())
    receipt = private_data_cli.evaluate(
        ["--paths", str(root), "--include-git-history"],
    )
    assert receipt.complete is True
    assert receipt.exit_code() == 1
    assert any(finding.code == "credential-pattern" for finding in receipt.findings)


def test_git_batch_trailing_stdout_is_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _source_repository(tmp_path)
    (root / "ordinary.txt").write_bytes(b"ordinary\n")
    _git(root, "add", "ordinary.txt")
    original_popen = private_data_scanner.subprocess.Popen
    script = (
        "import sys\n"
        "oid=sys.stdin.buffer.readline().strip()\n"
        "body=b'ordinary\\n'\n"
        "sys.stdout.buffer.write(oid+b' blob 9\\n'+body+b'\\n'+b'x'*1024)\n"
        "sys.stdout.buffer.flush()\n"
    )

    def inject_trailing_output(arguments, *args, **kwargs):
        vector = tuple(os.fspath(item) for item in arguments)
        if "cat-file" in vector and "--batch" in vector:
            return original_popen(
                (sys.executable, "-I", "-S", "-c", script),
                *args,
                **kwargs,
            )
        return original_popen(arguments, *args, **kwargs)

    monkeypatch.setattr(private_data_scanner, "MAX_GIT_BATCH_BUFFER_BYTES", 128, raising=False)
    monkeypatch.setattr(
        private_data_scanner.subprocess,
        "Popen",
        inject_trailing_output,
    )
    assert scan(root)[-1].reason == "git-batch-output-limit"


def test_every_git_process_wait_is_deadline_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _source_repository(tmp_path)
    (root / "ordinary.txt").write_text("ordinary\n", encoding="utf-8")
    _git(root, "add", "ordinary.txt")
    original_popen = private_data_scanner.subprocess.Popen
    waits = []

    class RecordingProcess:
        def __init__(self, process):
            self.process = process

        def wait(self, *args, **kwargs):
            waits.append(kwargs.get("timeout"))
            return self.process.wait(*args, **kwargs)

        def __getattr__(self, name):
            return getattr(self.process, name)

    def record_waits(*args, **kwargs):
        return RecordingProcess(original_popen(*args, **kwargs))

    monkeypatch.setattr(private_data_scanner.subprocess, "Popen", record_waits)
    assert scan(root) == ()
    assert waits
    assert all(timeout is not None for timeout in waits)


def test_index_blobs_use_one_batch_and_charge_before_body_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _source_repository(tmp_path)
    for name in ("one.txt", "two.txt"):
        (root / name).write_bytes(b"x" * 256)
    _git(root, "add", "one.txt", "two.txt")
    starts = 0
    original_start = private_data_scanner._start_git_batch
    original_copy = private_data_scanner.GitBatch._copy_body

    def counted_start(*args, **kwargs):
        nonlocal starts
        starts += 1
        return original_start(*args, **kwargs)

    def charged_copy(self, destination, declared_size, display, budget):
        assert budget.input_bytes >= declared_size
        return original_copy(self, destination, declared_size, display, budget)

    monkeypatch.setattr(private_data_scanner, "_start_git_batch", counted_start)
    monkeypatch.setattr(private_data_scanner.GitBatch, "_copy_body", charged_copy)
    assert scan(root) == ()
    assert starts == 1


def test_shared_budget_blocks_index_blob_before_body_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _source_repository(tmp_path)
    (root / "large.txt").write_bytes(b"x" * 1024)
    _git(root, "add", "large.txt")
    monkeypatch.setattr(private_data_scanner, "MAX_TOTAL_INPUT_BYTES", 100)
    monkeypatch.setattr(
        private_data_scanner.GitBatch,
        "_copy_body",
        lambda *_args, **_kwargs: pytest.fail("blob body read before budget rejection"),
    )
    assert scan(root)[-1].reason == "total-input-byte-limit"


@pytest.mark.parametrize(
    ("header", "reason"),
    (
        (b"missing\n", "git-batch-object-missing"),
        (b"0" * 40 + b" tree 1\n", "git-batch-type-invalid"),
        (b"1" * 40 + b" blob 1\n", "git-batch-oid-mismatch"),
        (b"0" * 40 + b" blob -1\n", "git-batch-size-invalid"),
        (b"0" * 40 + b" blob 01\n", "git-batch-size-invalid"),
    ),
)
def test_git_batch_header_is_exact(header: bytes, reason: str) -> None:
    with pytest.raises(private_data_scanner.GitInventoryError) as captured:
        private_data_scanner._parse_batch_header(header, "0" * 40, Path("index.txt"))
    assert captured.value.reason == reason


@pytest.mark.parametrize(
    ("delimiter", "reason"),
    (
        (b"", "git-batch-short-read"),
        (b"x", "git-batch-framing"),
        (b"\nextra", "git-batch-trailing-data"),
    ),
)
def test_git_batch_delimiter_is_exact(delimiter: bytes, reason: str) -> None:
    with pytest.raises(private_data_scanner.GitInventoryError) as captured:
        private_data_scanner._validate_batch_delimiter(delimiter, Path("index.txt"))
    assert captured.value.reason == reason


@pytest.mark.parametrize("alias_kind", ("same", "lexical", "hardlink"))
def test_duplicate_or_alias_roots_block_before_scanning(
    tmp_path: Path,
    alias_kind: str,
) -> None:
    first = tmp_path / "first.txt"
    first.write_text("synthetic\n", encoding="utf-8")
    if alias_kind == "same":
        second = first
    elif alias_kind == "lexical":
        second = tmp_path / "." / "first.txt"
    else:
        second = tmp_path / "second.txt"
        os.link(first, second)
    assert scan((first, second)) == (
        private_data_scanner.Finding(second.absolute(), "duplicate-root"),
    )


def test_one_budget_spans_mixed_source_and_artifact_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _source_repository(source)
    (source / "visible.txt").write_bytes(b"s" * 600)
    artifact = tmp_path / "candidate.bin"
    artifact.write_bytes(b"a" * 600)
    monkeypatch.setattr(private_data_scanner, "MAX_TOTAL_INPUT_BYTES", 1000)
    assert scan((source, artifact))[-1].reason == "total-input-byte-limit"


def test_explicit_generated_artifacts_and_bytes_after_two_megabytes_are_scanned(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "dist" / "candidate.bin"
    artifact.parent.mkdir()
    artifact.write_bytes(b"x" * 2_100_000 + _credential())
    findings = scan((tmp_path / "tests", artifact))
    assert (artifact, "credential-pattern") in {
        (finding.path, finding.reason) for finding in findings
    }


def test_every_bounded_archive_member_is_scanned(tmp_path: Path) -> None:
    import io
    import tarfile

    archive = tmp_path / "dist" / "candidate.tar.gz"
    archive.parent.mkdir()
    payload = b"x" * 2_100_000 + _private_key_marker()
    with tarfile.open(archive, "w:gz") as output:
        member = tarfile.TarInfo("nested/config.txt")
        member.size = len(payload)
        output.addfile(member, io.BytesIO(payload))
    findings = scan(archive)
    assert any(
        finding.path == Path(str(archive) + "!nested/config.txt")
        and finding.reason == "private-key"
        for finding in findings
    )


def test_realistic_reachy_wheelhouse_archive_is_streamed_past_old_16mib_limit(
    tmp_path: Path,
) -> None:
    import io
    import tarfile
    import zipfile

    archive = tmp_path / "tuntun-edge-realistic.tar.gz"
    wheel = io.BytesIO()
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_STORED) as output:
        output.writestr("synthetic_runtime/payload.bin", b"synthetic-wheel-bytes\n" * 1_100_000)
    payload = wheel.getvalue()
    with tarfile.open(archive, "w:gz") as output:
        member = tarfile.TarInfo("wheelhouse/synthetic_runtime-1.0-cp312-manylinux_aarch64.whl")
        member.size = len(payload)
        output.addfile(member, io.BytesIO(payload))
    assert len(payload) > 16 * 1024 * 1024
    assert scan(archive) == ()


def test_separate_raw_compressed_member_and_cumulative_limits_fail_closed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    import io
    import tarfile

    large = tmp_path / "large.txt"
    large.write_bytes(b"x" * 1025)
    monkeypatch.setattr(private_data_scanner, "MAX_RAW_FILE_BYTES", 1024)
    assert scan(large)[0].reason == "raw-byte-limit"

    archive = tmp_path / "bomb.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        for name in ("one.bin", "two.bin"):
            member = tarfile.TarInfo(name)
            member.size = 800
            output.addfile(member, io.BytesIO(b"z" * member.size))
    monkeypatch.setattr(private_data_scanner, "MAX_COMPRESSED_ARCHIVE_BYTES", 1)
    assert scan(archive)[0].reason == "compressed-byte-limit"
    monkeypatch.setattr(private_data_scanner, "MAX_COMPRESSED_ARCHIVE_BYTES", 1024 * 1024)
    monkeypatch.setattr(private_data_scanner, "MAX_ARCHIVE_MEMBER_BYTES", 700)
    assert any(item.reason == "archive-member-byte-limit" for item in scan(archive))
    monkeypatch.setattr(private_data_scanner, "MAX_ARCHIVE_MEMBER_BYTES", 1024)
    monkeypatch.setattr(private_data_scanner, "MAX_CUMULATIVE_EXPANDED_BYTES", 1500)
    assert any(item.reason == "cumulative-expanded-byte-limit" for item in scan(archive))


def test_missing_explicit_release_root_fails_closed(tmp_path: Path) -> None:
    missing = tmp_path / "dist"
    assert [(item.path, item.reason) for item in scan(missing)] == [(missing, "missing-root")]


def test_explicit_corrupt_archive_suffix_never_passes_as_an_ordinary_file(tmp_path: Path) -> None:
    for name in ("candidate.zip", "candidate.tar", "candidate.tar.gz", "candidate.tgz"):
        path = tmp_path / name
        path.write_bytes(b"not a parseable archive")
        assert [(item.path, item.reason) for item in scan(path)] == [(path, "corrupt-archive")]


def test_corrupt_archive_magic_without_suffix_fails_closed(tmp_path: Path) -> None:
    for name, prefix in (("zipish.bin", b"PK\x03\x04broken"), ("gzipish.bin", b"\x1f\x8bbroken")):
        path = tmp_path / name
        path.write_bytes(prefix)
        assert [(item.path, item.reason) for item in scan(path)] == [(path, "corrupt-archive")]


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (
        ("oversized_directory", "zip-central-directory-limit"),
        ("inconsistent_offset", "zip-central-directory-invalid"),
        ("dishonest_entry_count", "zip-central-directory-invalid"),
    ),
)
def test_zip_eocd_preflight_bounds_directory_before_zipfile_allocation(
    tmp_path: Path,
    mutation: str,
    reason: str,
) -> None:
    import struct
    import zipfile

    archive = tmp_path / "malformed.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("safe.txt", b"safe")
        output.writestr("also-safe.txt", b"safe")
    data = bytearray(archive.read_bytes())
    marker = data.rfind(b"PK\x05\x06")
    assert marker >= 0
    if mutation == "oversized_directory":
        struct.pack_into(
            "<I", data, marker + 12, private_data_scanner.MAX_ZIP_CENTRAL_DIRECTORY_BYTES + 1
        )
    else:
        if mutation == "inconsistent_offset":
            offset = struct.unpack_from("<I", data, marker + 16)[0]
            struct.pack_into("<I", data, marker + 16, offset + 1)
        else:
            struct.pack_into("<H", data, marker + 8, 1)
            struct.pack_into("<H", data, marker + 10, 1)
    archive.write_bytes(data)
    assert scan(archive)[0].reason == reason


def test_nested_archive_member_is_recursively_scanned_under_the_same_budget(tmp_path: Path) -> None:
    import io
    import tarfile
    import zipfile

    nested = io.BytesIO()
    with zipfile.ZipFile(nested, "w", compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr("nested/config.txt", _credential())
    outer = tmp_path / "candidate.tar.gz"
    with tarfile.open(outer, "w:gz") as output:
        member = tarfile.TarInfo("wheelhouse/example.whl")
        member.size = len(nested.getvalue())
        output.addfile(member, io.BytesIO(nested.getvalue()))
    assert any(item.reason == "credential-pattern" for item in scan(outer))


def test_filesystem_and_archive_symlink_or_special_entries_fail_closed(tmp_path: Path) -> None:
    import os
    import tarfile

    target = tmp_path / "target.txt"
    target.write_text("synthetic")
    (tmp_path / "alias.txt").symlink_to(target)
    os.mkfifo(tmp_path / "named-pipe")
    archive = tmp_path / "links.tar"
    with tarfile.open(archive, "w") as output:
        symlink = tarfile.TarInfo("alias")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "target"
        output.addfile(symlink)
        device = tarfile.TarInfo("device")
        device.type = tarfile.CHRTYPE
        output.addfile(device)
    reasons = {item.reason for item in scan(tmp_path)}
    assert {"filesystem-symlink", "filesystem-special", "unsafe-archive-member"} <= reasons


def test_cumulative_actual_expansion_is_shared_across_archives(
    tmp_path: Path,
    monkeypatch,
) -> None:
    import gzip
    import io
    import tarfile

    archives = []
    for index in range(2):
        archive = tmp_path / f"part-{index}.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            member = tarfile.TarInfo("payload.bin")
            member.size = 800
            output.addfile(member, io.BytesIO(b"x" * member.size))
        archives.append(archive)
    one_archive_expansion = len(gzip.decompress(archives[0].read_bytes()))
    monkeypatch.setattr(
        private_data_scanner,
        "MAX_CUMULATIVE_EXPANDED_BYTES",
        one_archive_expansion + 512,
    )
    assert scan(archives[0]) == ()
    assert any(item.reason == "cumulative-expanded-byte-limit" for item in scan(tuple(archives)))


def test_files_input_bytes_and_archive_members_share_one_budget_across_roots(
    tmp_path: Path,
    monkeypatch,
) -> None:
    import io
    import tarfile

    raw = []
    for index in range(2):
        path = tmp_path / f"raw-{index}.txt"
        path.write_bytes(b"x" * 800)
        raw.append(path)
    monkeypatch.setattr(private_data_scanner, "MAX_TOTAL_INPUT_BYTES", 1500)
    assert scan(tuple(raw))[-1].reason == "total-input-byte-limit"
    monkeypatch.setattr(private_data_scanner, "MAX_TOTAL_INPUT_BYTES", 4096)
    monkeypatch.setattr(private_data_scanner, "MAX_FILES", 1)
    assert scan(tuple(raw))[-1].reason == "file-count-limit"

    monkeypatch.setattr(private_data_scanner, "MAX_FILES", 10)
    archives = []
    for index in range(2):
        archive = tmp_path / f"members-{index}.tar"
        with tarfile.open(archive, "w") as output:
            member = tarfile.TarInfo("payload.bin")
            member.size = 1
            output.addfile(member, io.BytesIO(b"x"))
        archives.append(archive)
    monkeypatch.setattr(private_data_scanner, "MAX_TOTAL_INPUT_BYTES", 100_000)
    monkeypatch.setattr(private_data_scanner, "MAX_ARCHIVE_MEMBERS", 1)
    assert scan(tuple(archives))[-1].reason == "archive-member-limit"


def test_streaming_walk_stops_before_materializing_a_million_entries(
    tmp_path: Path,
    monkeypatch,
) -> None:
    class Entry:
        def __init__(self, index):
            self.name = f"missing-{index}"

    class LazyMillion:
        emitted = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            return self

        def __next__(self):
            if self.emitted == 1_000_000:
                raise StopIteration
            item = Entry(self.emitted)
            self.emitted += 1
            return item

    lazy = LazyMillion()
    original_stat = private_data_scanner.os.stat

    def bounded_stat(path, *args, dir_fd=None, **kwargs):
        if dir_fd is not None and str(path).startswith("missing-"):
            return type(
                "Metadata",
                (),
                {
                    "st_mode": private_data_scanner.stat.S_IFLNK,
                    "st_dev": 1,
                    "st_ino": 1,
                    "st_size": 0,
                    "st_mtime_ns": 0,
                    "st_ctime_ns": 0,
                },
            )()
        return original_stat(path, *args, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(private_data_scanner, "MAX_PATH_ENTRIES", 3)
    monkeypatch.setattr(private_data_scanner.os, "scandir", lambda _path: lazy)
    monkeypatch.setattr(private_data_scanner.os, "stat", bounded_stat)
    assert any(item.reason == "path-entry-limit" for item in scan(tmp_path))
    assert lazy.emitted == 4


def _ustar_header(name: bytes, size: int, kind: bytes = b"0") -> bytes:
    header = bytearray(512)
    header[0 : len(name)] = name
    for offset, width, value in (
        (100, 8, 0o644),
        (108, 8, 0),
        (116, 8, 0),
        (124, 12, size),
        (136, 12, 0),
    ):
        encoded = (f"{value:0{width - 1}o}\0").encode("ascii")
        header[offset : offset + width] = encoded
    header[148:156] = b"        "
    header[156:157] = kind
    header[257:265] = b"ustar\x0000"
    checksum = sum(header)
    header[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    return bytes(header)


@pytest.mark.parametrize("kind", (b"x", b"g", b"L", b"K"))
def test_tar_extended_metadata_is_blocked_before_declared_payload_allocation(
    tmp_path: Path,
    kind: bytes,
) -> None:
    archive = tmp_path / "hostile.tar"
    archive.write_bytes(
        _ustar_header(b"metadata", private_data_scanner.MAX_TAR_METADATA_BYTES + 1, kind)
    )
    assert scan(archive)[0].reason == "tar-metadata-limit"


def test_tar_and_gzip_trailing_bytes_are_bounded_and_must_be_zero(
    tmp_path: Path,
    monkeypatch,
) -> None:
    import gzip

    monkeypatch.setattr(private_data_scanner, "MAX_TAR_TRAILING_PADDING_BYTES", 1024)
    monkeypatch.setattr(private_data_scanner, "MAX_GZIP_TRAILING_PADDING_BYTES", 1024)
    end = b"\0" * 1024
    excessive_tar = tmp_path / "tar-padding.tar.gz"
    excessive_tar.write_bytes(gzip.compress(end + b"\0" * 1536, mtime=0))
    assert scan(excessive_tar)[0].reason == "tar-trailing-padding-limit"

    valid = tmp_path / "gzip-padding.tar.gz"
    compressed = gzip.compress(end, mtime=0)
    valid.write_bytes(compressed + b"\0" * 1025)
    assert scan(valid)[0].reason == "gzip-trailing-padding-limit"
    valid.write_bytes(compressed + b"\0" * 32 + b"x")
    assert scan(valid)[0].reason == "gzip-trailing-data"


def test_gzip_header_crc_is_validated(tmp_path: Path) -> None:
    import gzip
    import struct
    import zlib

    compressed = gzip.compress(b"\0" * 1024, mtime=0)
    header = bytearray(compressed[:10])
    header[3] |= 0x02
    crc = zlib.crc32(header) & 0xFFFF
    valid = tmp_path / "valid-fhcrc.tar.gz"
    valid.write_bytes(bytes(header) + struct.pack("<H", crc) + compressed[10:])
    assert scan(valid) == ()
    invalid = tmp_path / "invalid-fhcrc.tar.gz"
    invalid.write_bytes(bytes(header) + struct.pack("<H", crc ^ 1) + compressed[10:])
    assert scan(invalid)[0].reason == "corrupt-archive"


@pytest.mark.parametrize("container", ("zip_comment", "zip_extra", "tar_header", "gzip_comment"))
def test_archive_metadata_bytes_are_pattern_scanned(tmp_path: Path, container: str) -> None:
    import gzip
    import struct
    import zipfile

    secret = _credential(b"M")
    path = tmp_path / (container + (".zip" if container.startswith("zip") else ".tar.gz"))
    if container.startswith("zip"):
        with zipfile.ZipFile(path, "w") as archive:
            item = zipfile.ZipInfo("safe.txt")
            if container == "zip_extra":
                item.extra = struct.pack("<HH", 0xCAFE, len(secret)) + secret
            archive.writestr(item, b"synthetic")
            if container == "zip_comment":
                archive.comment = secret
    elif container == "tar_header":
        header = bytearray(_ustar_header(b"safe.txt", 0))
        header[265 : 265 + len(secret)] = secret
        header[148:156] = b"        "
        header[148:156] = f"{sum(header):06o}\0 ".encode()
        path.write_bytes(gzip.compress(bytes(header) + b"\0" * 1024, mtime=0))
    else:
        payload = gzip.compress(b"\0" * 1024, mtime=0)
        fixed = bytearray(payload[:10])
        fixed[3] |= 0x10
        path.write_bytes(bytes(fixed) + secret + b"\0" + payload[10:])
    assert any(item.reason == "credential-pattern" for item in scan(path))


def test_cli_preserves_explicit_symlink_for_nofollow_rejection(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    target = tmp_path / "target.txt"
    target.write_text("synthetic")
    alias = tmp_path / "explicit.txt"
    alias.symlink_to(target)
    monkeypatch.setattr(private_data_scanner.sys, "argv", ["verify_private_data.py", str(alias)])
    assert private_data_scanner.main() == 1
    assert "filesystem-symlink" in capsys.readouterr().out


@pytest.mark.parametrize("generated_name", ("dist", "var", "node_modules"))
def test_nested_generated_name_is_not_a_skip_boundary(
    tmp_path: Path,
    generated_name: str,
) -> None:
    nested = tmp_path / "src" / generated_name / "tracked-secret.txt"
    nested.parent.mkdir(parents=True)
    nested.write_bytes(_credential())
    assert any(item.reason == "credential-pattern" for item in scan(tmp_path))


def test_tracked_file_inside_exact_generated_root_is_scanned(tmp_path: Path) -> None:
    import subprocess

    subprocess.run(("git", "init", "-q", str(tmp_path)), check=True)
    secret = tmp_path / "dist" / "tracked-secret.txt"
    secret.parent.mkdir()
    secret.write_bytes(_credential())
    subprocess.run(("git", "-C", str(tmp_path), "add", "dist/tracked-secret.txt"), check=True)
    assert any(item.reason == "credential-pattern" for item in scan(tmp_path))


def test_explicit_generated_root_does_not_skip_its_nested_generated_name(tmp_path: Path) -> None:
    root = _source_repository(tmp_path)
    (root / ".gitignore").write_text("var/\n", encoding="utf-8")
    _git(root, "add", ".gitignore")
    explicit = root / "var"
    secret = explicit / "node_modules" / "secret.txt"
    secret.parent.mkdir(parents=True)
    secret.write_bytes(_credential())
    assert scan(root) == ()
    assert any(item.reason == "credential-pattern" for item in scan(explicit))


def test_zip_directory_payload_duplicate_and_unsafe_virtual_names_block(tmp_path: Path) -> None:
    import stat
    import zipfile

    for name, write in (
        ("payload.zip", lambda value: value.writestr("secret.txt/", _credential())),
        (
            "duplicate.zip",
            lambda value: (value.writestr("same.txt", b"one"), value.writestr("same.txt", b"two")),
        ),
        ("escape.zip", lambda value: value.writestr("../escape.txt", b"synthetic")),
    ):
        archive = tmp_path / name
        with zipfile.ZipFile(archive, "w") as output:
            if name == "duplicate.zip":
                with pytest.warns(UserWarning, match=r"Duplicate name: 'same\.txt'"):
                    write(output)
            else:
                write(output)
        assert any(item.reason == "unsafe-archive-member" for item in scan(archive))
    valid = tmp_path / "directory.zip"
    with zipfile.ZipFile(valid, "w") as output:
        item = zipfile.ZipInfo("empty/")
        item.external_attr = (stat.S_IFDIR | 0o755) << 16
        output.writestr(item, b"")
    assert scan(valid) == ()


def test_special_tar_member_with_nonzero_body_is_rejected_before_body_read(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "special.tar"
    archive.write_bytes(_ustar_header(b"device", 2 * 1024 * 1024 * 1024, b"3"))
    assert scan(archive)[0].reason == "unsafe-archive-member"


def test_named_file_and_queued_directory_replacement_cannot_attest_substitute(
    tmp_path: Path,
    monkeypatch,
) -> None:
    clean = tmp_path / "clean.txt"
    clean.write_text("synthetic")
    substitute = tmp_path / "substitute.txt"
    substitute.write_bytes(_credential())
    original_read = private_data_scanner.FrozenFileView.read
    replaced = False

    def replacing_read(self, size=-1):
        nonlocal replaced
        if not replaced:
            replaced = True
            clean.replace(tmp_path / "old.txt")
            substitute.replace(clean)
        return original_read(self, size)

    monkeypatch.setattr(private_data_scanner.FrozenFileView, "read", replacing_read)
    assert any(item.reason == "input-changed-during-scan" for item in scan(clean))

    directory = tmp_path / "tree"
    directory.mkdir()
    (directory / "safe.txt").write_text("synthetic")
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "secret.txt").write_bytes(_credential(b"B"))
    original_scandir = private_data_scanner.os.scandir
    swapped = False

    def replacing_scandir(path):
        nonlocal swapped
        if isinstance(path, int) and not swapped:
            swapped = True
            directory.replace(tmp_path / "old-tree")
            replacement.replace(directory)
        return original_scandir(path)

    monkeypatch.setattr(private_data_scanner.os, "scandir", replacing_scandir)
    findings = scan(directory)
    assert any(
        item.reason in {"input-changed-during-scan", "credential-pattern"} for item in findings
    )


@pytest.mark.parametrize("replacement_kind", ("regular", "symlink", "fifo"))
def test_walk_entry_replacement_between_first_stat_and_open_is_blocked(
    tmp_path: Path,
    monkeypatch,
    replacement_kind: str,
) -> None:
    tree = tmp_path / "walk-race"
    tree.mkdir()
    candidate = tree / "race.txt"
    candidate.write_text("synthetic")
    substitute = tree / "substitute"
    substitute.write_bytes(_credential(b"R"))
    target = tree / "target"
    target.write_text("synthetic")
    original_stat = private_data_scanner.os.stat
    calls = 0

    def replacing_stat(path, *args, dir_fd=None, **kwargs):
        nonlocal calls
        if dir_fd is not None and str(path) == "race.txt":
            calls += 1
            if calls == 2:
                candidate.unlink()
                if replacement_kind == "regular":
                    substitute.replace(candidate)
                elif replacement_kind == "symlink":
                    candidate.symlink_to(target.name)
                else:
                    private_data_scanner.os.mkfifo(candidate)
        return original_stat(path, *args, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(private_data_scanner.os, "stat", replacing_stat)
    findings = scan(tree)
    assert calls >= 2
    assert any(item.reason == "input-changed-during-scan" for item in findings)
