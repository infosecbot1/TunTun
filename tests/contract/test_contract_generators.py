from __future__ import annotations

# The import split below deliberately bootstraps the uninstalled root namespace.
# ruff: noqa: E402
import hashlib
import json
import os
import stat
import subprocess
import sys
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Protocol, cast

# The root project is not an installed package; preserve package-import coverage
# without changing workspace metadata or adding a suite-wide import side effect.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest
import tuntun_contracts
import yaml  # type: ignore[import-untyped]  # PyYAML 6 has no py.typed marker.
from tuntun_contracts.base import ContractModel, registered_contract_models

from scripts import contract_generator_common, generate_openapi, generate_schemas
from scripts.assurance_common import (
    AssuranceInputError,
    FrozenRegularFile,
    lexical_path,
    read_regular_file,
)
from scripts.contract_generator_common import GeneratorError

SCHEMA_OUTPUT = Path("packages/contracts/schema/v1/contracts.schema.json")
OPENAPI_OUTPUT = Path("packages/contracts/openapi/admin-v1.yaml")
REQUIRED_TASK4_MODELS = frozenset(
    {
        "tuntun_contracts.base.Commitment",
        "tuntun_contracts.events.EventEnvelope",
        "tuntun_contracts.events.SignedEventEnvelope",
        "tuntun_contracts.events.StopRequestedPayload",
        "tuntun_contracts.events.WakeDetectedPayload",
    }
)


class _GeneratorModule(Protocol):
    __name__: str
    OUTPUT_PATH: Path

    def render(self) -> bytes: ...

    def main(self, argv: Sequence[str] | None = None) -> int: ...


def _mapping(value: object) -> Mapping[str, object]:
    assert isinstance(value, dict)
    assert all(isinstance(key, str) for key in value)
    return cast(dict[str, object], value)


def _model_name(model: type[ContractModel]) -> str:
    return f"{model.__module__}.{model.__qualname__}"


def _public_contract_models() -> tuple[type[ContractModel], ...]:
    models: list[type[ContractModel]] = []
    for export_name in tuntun_contracts.__all__:
        exported = getattr(tuntun_contracts, export_name)
        if (
            isinstance(exported, type)
            and issubclass(exported, ContractModel)
            and exported is not ContractModel
        ):
            models.append(exported)
    return tuple(sorted(models, key=_model_name))


def _public_model_names() -> tuple[str, ...]:
    return tuple(_model_name(model) for model in _public_contract_models())


def _assert_registry_matches_public_exports(
    models: tuple[type[ContractModel], ...],
) -> None:
    names = tuple(_model_name(model) for model in models)
    assert names == tuple(sorted(names))
    assert len(set(names)) == len(names)
    assert frozenset(names) >= REQUIRED_TASK4_MODELS
    assert all(name.startswith("tuntun_contracts.") for name in names)
    assert models == _public_contract_models()


def _subprocess_render(module_name: str, *, hash_seed: str) -> bytes:
    source = (
        "import sys\n"
        f"from scripts import {module_name} as generator\n"
        "sys.stdout.buffer.write(generator.render())\n"
    )
    environment = {**os.environ, "PYTHONHASHSEED": hash_seed}
    completed = subprocess.run(
        [sys.executable, "-c", source],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
    )
    assert completed.stderr == b""
    return completed.stdout


def _subprocess_cli(
    script: str,
    arguments: Sequence[str],
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, script, *arguments],
        cwd=ROOT,
        env={**os.environ, "PYTHONHASHSEED": "1"},
        check=False,
        capture_output=True,
    )


def _walk_refs(value: object) -> Iterator[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref":
                assert isinstance(child, str)
                yield child
            else:
                yield from _walk_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_refs(child)


def _resolve_local_ref(document: object, reference: str) -> object:
    assert reference.startswith("#/")
    current = document
    for encoded in reference[2:].split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            current = current[token]
        elif isinstance(current, list):
            current = current[int(token)]
        else:
            raise AssertionError(f"reference traversed a scalar: {reference}")
    return current


def _tree_snapshot(root: Path) -> tuple[tuple[str, int, int, bytes], ...]:
    if not root.exists() and not root.is_symlink():
        return ()
    snapshot: list[tuple[str, int, int, bytes]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        metadata = path.lstat()
        payload = b""
        if stat.S_ISREG(metadata.st_mode):
            payload = read_regular_file(path, max_bytes=4 * 1024 * 1024)
        elif stat.S_ISLNK(metadata.st_mode):
            payload = os.readlink(path).encode("utf-8")
        snapshot.append(
            (
                path.relative_to(root).as_posix(),
                metadata.st_mode,
                metadata.st_size,
                hashlib.sha256(payload).digest(),
            )
        )
    return tuple(snapshot)


def test_registry_is_closed_exhaustive_immutable_and_package_owned() -> None:
    registered = registered_contract_models()
    assert type(registered) is tuple
    _assert_registry_matches_public_exports(registered)
    assert registered is registered_contract_models()
    assert registered is tuntun_contracts._REGISTERED_CONTRACT_MODELS


def test_registry_oracle_adapts_and_rejects_every_public_model_omission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_models = _public_contract_models()
    for omitted in public_models:
        with pytest.raises(AssertionError):
            _assert_registry_matches_public_exports(
                tuple(model for model in public_models if model is not omitted)
            )

    class FuturePublicModel(ContractModel):
        marker: str

    FuturePublicModel.__module__ = "tuntun_contracts.future"
    monkeypatch.setattr(
        tuntun_contracts,
        "FuturePublicModel",
        FuturePublicModel,
        raising=False,
    )
    monkeypatch.setattr(
        tuntun_contracts,
        "__all__",
        (*tuntun_contracts.__all__, "FuturePublicModel"),
    )
    expanded_models: tuple[type[ContractModel], ...] = (
        *registered_contract_models(),
        FuturePublicModel,
    )
    expanded = tuple(sorted(expanded_models, key=_model_name))
    _assert_registry_matches_public_exports(expanded)


def test_generators_freeze_metadata_exact_models_and_independent_process_determinism() -> None:
    assert generate_schemas.OUTPUT_PATH == SCHEMA_OUTPUT
    assert generate_openapi.OUTPUT_PATH == OPENAPI_OUTPUT

    schema_first = _subprocess_render("generate_schemas", hash_seed="1")
    schema_second = _subprocess_render("generate_schemas", hash_seed="987654")
    openapi_first = _subprocess_render("generate_openapi", hash_seed="1")
    openapi_second = _subprocess_render("generate_openapi", hash_seed="987654")
    assert schema_first == schema_second == generate_schemas.render()
    assert openapi_first == openapi_second == generate_openapi.render()

    expected_models = _public_model_names()
    schema = _mapping(json.loads(schema_first))
    assert set(schema) == {"$schema", "schema_version", "models"}
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["schema_version"] == "1.0"
    assert tuple(_mapping(schema["models"])) == expected_models

    openapi = _mapping(yaml.safe_load(openapi_first))
    assert set(openapi) == {"openapi", "info", "paths", "components"}
    assert openapi["openapi"] == "3.1.0"
    assert openapi["info"] == {
        "title": "Tuntun Admin API",
        "version": "1.0.0",
        "description": "Foundation contract components; no HTTP paths are owned yet.",
    }
    assert openapi["paths"] == {}
    components = _mapping(openapi["components"])
    assert set(components) == {"schemas"}
    assert tuple(_mapping(components["schemas"])) == expected_models


@pytest.mark.parametrize(
    ("script", "output"),
    (
        ("scripts/generate_schemas.py", SCHEMA_OUTPUT),
        ("scripts/generate_openapi.py", OPENAPI_OUTPUT),
    ),
)
def test_generator_process_cli_has_closed_error_codes_and_nonmutating_check(
    script: str,
    output: Path,
) -> None:
    before = _tree_snapshot(ROOT / output.parent)
    for arguments in (
        (),
        ("--check", "--write"),
        ("--check", "--check"),
        ("--chec",),
        ("--unknown",),
    ):
        completed = _subprocess_cli(script, arguments)
        assert completed.returncode == 1
        assert completed.stdout == completed.stderr == b""
        assert _tree_snapshot(ROOT / output.parent) == before
    completed = _subprocess_cli(script, ("--check",))
    assert completed.returncode == 0
    assert completed.stdout == completed.stderr == b""
    assert _tree_snapshot(ROOT / output.parent) == before


def test_every_generated_local_reference_resolves() -> None:
    documents = (
        json.loads(generate_schemas.render()),
        yaml.safe_load(generate_openapi.render()),
    )
    for document in documents:
        references = tuple(_walk_refs(document))
        assert references
        for reference in references:
            assert reference.startswith("#/")
            assert _resolve_local_ref(document, reference) is not None


def test_duplicate_fully_qualified_model_names_fail_before_schema_render(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def make_collision() -> type[ContractModel]:
        class Collision(ContractModel):
            value: str

        return Collision

    duplicate_models = (make_collision(), make_collision())

    def duplicate_registry() -> tuple[type[ContractModel], ...]:
        return duplicate_models

    for generator in (generate_schemas, generate_openapi):
        monkeypatch.setattr(generator, "registered_contract_models", duplicate_registry)
        with pytest.raises(GeneratorError, match="duplicate fully qualified"):
            generator.render()


@pytest.mark.parametrize("generator", (generate_schemas, generate_openapi))
def test_nondeterministic_render_fails_without_output_mutation(
    generator: _GeneratorModule,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / generator.__name__
    parent.mkdir()
    output = parent / generator.OUTPUT_PATH.name
    monkeypatch.setattr(generator, "OUTPUT_PATH", output)
    output.write_bytes(b"first render\n")
    output.chmod(0o600)
    renders = iter((b"first render\n", b"second render\n"))
    render_count = 0

    def nondeterministic_render() -> bytes:
        nonlocal render_count
        render_count += 1
        return next(renders)

    monkeypatch.setattr(generator, "render", nondeterministic_render)
    before = _tree_snapshot(parent)
    assert generator.main(["--check"]) == 1
    assert render_count == 2
    assert _tree_snapshot(parent) == before


@pytest.mark.parametrize("generator", (generate_schemas, generate_openapi))
def test_generator_cli_is_closed_and_check_mode_never_mutates(
    generator: _GeneratorModule,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / generator.__name__
    parent.mkdir()
    owned = parent / generator.OUTPUT_PATH.name
    monkeypatch.setattr(generator, "OUTPUT_PATH", owned)
    main = generator.main
    render = generator.render

    for argv in ([], ["--check", "--write"], ["--check", "--check"], ["--chec"], ["--unknown"]):
        assert main(argv) == 1

    before_missing = _tree_snapshot(parent)
    assert main(["--check"]) == 1
    assert _tree_snapshot(parent) == before_missing

    owned.write_bytes(b"stale\n")
    before_stale = _tree_snapshot(parent)
    assert main(["--check"]) == 1
    assert _tree_snapshot(parent) == before_stale

    assert main(["--write"]) == 0
    assert stat.S_IMODE(owned.stat().st_mode) == 0o600
    assert owned.read_bytes() == render()
    before_current = _tree_snapshot(parent)
    assert main(["--check"]) == 0
    assert _tree_snapshot(parent) == before_current

    extra = parent / "extra.generated"
    extra.write_text("unexpected\n", encoding="utf-8")
    before_extra = _tree_snapshot(parent)
    assert main(["--check"]) == 1
    assert _tree_snapshot(parent) == before_extra
    extra.unlink()

    target = tmp_path / f"{generator.__name__}-outside"
    target.write_bytes(b"outside\n")
    extra.symlink_to(target)
    before_extra_symlink = _tree_snapshot(parent)
    assert main(["--check"]) == 1
    assert _tree_snapshot(parent) == before_extra_symlink
    assert target.read_bytes() == b"outside\n"
    extra.unlink()

    os.mkfifo(extra, mode=0o600)
    before_special = _tree_snapshot(parent)
    assert main(["--check"]) == 1
    assert _tree_snapshot(parent) == before_special
    extra.unlink()

    owned.unlink()
    owned.symlink_to(target)
    before_output_symlink = _tree_snapshot(parent)
    assert main(["--check"]) == 1
    assert _tree_snapshot(parent) == before_output_symlink
    assert target.read_bytes() == b"outside\n"
    owned.unlink()

    os.mkfifo(owned, mode=0o600)
    before_output_special = _tree_snapshot(parent)
    assert main(["--check"]) == 1
    assert _tree_snapshot(parent) == before_output_special


@pytest.mark.parametrize("generator", (generate_schemas, generate_openapi))
def test_generator_rejects_symlinked_output_parent_without_mutation(
    generator: _GeneratorModule,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real_parent, target_is_directory=True)
    output = alias / "must-not-be-created" / generator.OUTPUT_PATH.name
    monkeypatch.setattr(generator, "OUTPUT_PATH", output)
    before = _tree_snapshot(real_parent)
    assert generator.main(["--check"]) == 1
    assert generator.main(["--write"]) == 1
    assert _tree_snapshot(real_parent) == before


@pytest.mark.parametrize("generator", (generate_schemas, generate_openapi))
def test_write_failure_preserves_prior_output_and_removes_private_temp(
    generator: _GeneratorModule,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / generator.__name__
    parent.mkdir()
    output = parent / generator.OUTPUT_PATH.name
    output.write_bytes(b"prior bytes\n")
    output.chmod(0o600)
    monkeypatch.setattr(generator, "OUTPUT_PATH", output)

    def fail_replace(source_name: str, destination_name: str, parent_fd: int) -> None:
        raise OSError("injected replace failure")

    monkeypatch.setattr(contract_generator_common, "_atomic_replace", fail_replace)
    before = _tree_snapshot(parent)
    assert generator.main(["--write"]) == 1
    assert _tree_snapshot(parent) == before
    assert output.read_bytes() == b"prior bytes\n"


@pytest.mark.parametrize("generator", (generate_schemas, generate_openapi))
def test_write_rejects_parent_swap_between_baseline_and_publication(
    generator: _GeneratorModule,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / generator.__name__
    parent.mkdir()
    replacement = tmp_path / f"{generator.__name__}-replacement"
    replacement.mkdir()
    old_tree = tmp_path / f"{generator.__name__}-old"
    output = parent / generator.OUTPUT_PATH.name
    monkeypatch.setattr(generator, "OUTPUT_PATH", output)
    original_snapshot = contract_generator_common._owned_snapshot
    swapped = False

    def swap_after_baseline(
        output_path: Path,
        *,
        allow_missing: bool,
        output_parent: contract_generator_common.OutputParent | None = None,
    ) -> tuple[FrozenRegularFile, ...]:
        nonlocal swapped
        result = original_snapshot(
            output_path,
            allow_missing=allow_missing,
            output_parent=output_parent,
        )
        if allow_missing and not swapped:
            parent.rename(old_tree)
            replacement.rename(parent)
            swapped = True
        return result

    monkeypatch.setattr(contract_generator_common, "_owned_snapshot", swap_after_baseline)
    assert generator.main(["--write"]) == 1
    assert swapped
    assert _tree_snapshot(parent) == ()
    assert _tree_snapshot(old_tree) == ()


@pytest.mark.parametrize("generator", (generate_schemas, generate_openapi))
@pytest.mark.parametrize("baseline", (None, b"prior bytes\n"))
def test_write_rolls_back_parent_swap_inside_atomic_replace(
    generator: _GeneratorModule,
    baseline: bytes | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / generator.__name__
    parent.mkdir()
    replacement = tmp_path / f"{generator.__name__}-replacement"
    replacement.mkdir()
    replacement_sentinel = replacement / "replacement.sentinel"
    replacement_sentinel.write_bytes(b"replacement tree\n")
    old_tree = tmp_path / f"{generator.__name__}-old"
    output = parent / generator.OUTPUT_PATH.name
    if baseline is not None:
        output.write_bytes(baseline)
        output.chmod(0o640)
    monkeypatch.setattr(generator, "OUTPUT_PATH", output)
    old_before = _tree_snapshot(parent)
    replacement_before = _tree_snapshot(replacement)
    real_replace = contract_generator_common._atomic_replace
    swapped = False

    def swap_inside_replace(source_name: str, destination_name: str, parent_fd: int) -> None:
        nonlocal swapped
        if not swapped:
            parent.rename(old_tree)
            replacement.rename(parent)
            swapped = True
        real_replace(source_name, destination_name, parent_fd)

    monkeypatch.setattr(contract_generator_common, "_atomic_replace", swap_inside_replace)
    assert generator.main(["--write"]) == 1
    assert swapped
    assert _tree_snapshot(parent) == replacement_before
    assert _tree_snapshot(old_tree) == old_before


@pytest.mark.parametrize("generator", (generate_schemas, generate_openapi))
@pytest.mark.parametrize("baseline", (None, b"prior bytes\n"))
def test_parent_swap_rollback_failure_returns_one_and_cleans_temps(
    generator: _GeneratorModule,
    baseline: bytes | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / generator.__name__
    parent.mkdir()
    replacement = tmp_path / f"{generator.__name__}-replacement"
    replacement.mkdir()
    replacement_sentinel = replacement / "replacement.sentinel"
    replacement_sentinel.write_bytes(b"replacement tree\n")
    old_tree = tmp_path / f"{generator.__name__}-old"
    output = parent / generator.OUTPUT_PATH.name
    if baseline is not None:
        output.write_bytes(baseline)
        output.chmod(0o640)
    monkeypatch.setattr(generator, "OUTPUT_PATH", output)
    old_before = _tree_snapshot(parent)
    replacement_before = _tree_snapshot(replacement)
    real_replace = contract_generator_common._atomic_replace
    real_write = contract_generator_common._write_atomically
    swapped = False

    def swap_inside_replace(source_name: str, destination_name: str, parent_fd: int) -> None:
        nonlocal swapped
        if not swapped:
            parent.rename(old_tree)
            replacement.rename(parent)
            swapped = True
        real_replace(source_name, destination_name, parent_fd)

    rollback_failures = 0

    def fail_rollback(source_or_destination: str, *arguments: object) -> None:
        nonlocal rollback_failures
        rollback_failures += 1
        raise OSError(f"injected rollback failure: {source_or_destination}")

    observed_errors: list[str] = []

    def capture_rollback_error(output_path: Path, rendered: bytes) -> None:
        try:
            real_write(output_path, rendered)
        except GeneratorError as error:
            observed_errors.append(str(error))
            raise

    monkeypatch.setattr(contract_generator_common, "_atomic_replace", swap_inside_replace)
    rollback_operation = "_rollback_unlink" if baseline is None else "_rollback_replace"
    monkeypatch.setattr(contract_generator_common, rollback_operation, fail_rollback)
    monkeypatch.setattr(contract_generator_common, "_write_atomically", capture_rollback_error)
    assert generator.main(["--write"]) == 1
    assert swapped
    assert rollback_failures == 1
    assert observed_errors == ["publication failed and rollback failed"]
    assert _tree_snapshot(parent) == replacement_before
    assert _tree_snapshot(old_tree) != old_before
    assert all(not entry[0].startswith(".") for entry in _tree_snapshot(old_tree))


@pytest.mark.parametrize("generator", (generate_schemas, generate_openapi))
def test_task3_race_signal_fails_check_closed_without_generator_mutation(
    generator: _GeneratorModule,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / generator.__name__
    parent.mkdir()
    output = parent / generator.OUTPUT_PATH.name
    monkeypatch.setattr(generator, "OUTPUT_PATH", output)
    assert generator.main(["--write"]) == 0
    before = _tree_snapshot(parent)
    original_read = read_regular_file

    def race_read(path: Path, *, max_bytes: int) -> bytes:
        if lexical_path(path) == lexical_path(output):
            raise AssuranceInputError(path, "input-changed-during-scan")
        return original_read(path, max_bytes=max_bytes)

    monkeypatch.setattr(contract_generator_common, "read_regular_file", race_read)
    assert generator.main(["--check"]) == 1
    assert _tree_snapshot(parent) == before
