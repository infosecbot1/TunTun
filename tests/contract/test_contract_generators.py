from __future__ import annotations

# The import split below deliberately bootstraps the uninstalled root namespace.
# ruff: noqa: E402
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import stat
import struct
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import NoReturn, Protocol, cast

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
        if "propertyName" in value and "mapping" in value:
            assert isinstance(value["propertyName"], str)
            mapping = value["mapping"]
            assert isinstance(mapping, dict)
            for target in mapping.values():
                assert isinstance(target, str)
                yield target
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
        json.loads(read_regular_file(ROOT / SCHEMA_OUTPUT, max_bytes=4 * 1024 * 1024)),
        yaml.safe_load(read_regular_file(ROOT / OPENAPI_OUTPUT, max_bytes=4 * 1024 * 1024)),
    )
    for document in documents:
        references = tuple(_walk_refs(document))
        assert references
        for reference in references:
            assert reference.startswith("#/")
            assert _resolve_local_ref(document, reference) is not None


def test_schema_reference_rewrite_is_limited_to_supported_reference_positions() -> None:
    source: dict[str, object] = {
        "$ref": "#/$defs/Root",
        "discriminator": {
            "propertyName": "kind",
            "mapping": {
                "one": "#/$defs/One",
                "two": "#/$defs/Two",
            },
        },
        "default": "#/$defs/MustRemainLiteral",
        "metadata": {"mapping": {"literal": "#/$defs/AlsoLiteral"}},
    }
    assert contract_generator_common._rewrite_local_refs(
        source,
        model_pointer="#/models/example.Model",
    ) == {
        "$ref": "#/models/example.Model/$defs/Root",
        "discriminator": {
            "propertyName": "kind",
            "mapping": {
                "one": "#/models/example.Model/$defs/One",
                "two": "#/models/example.Model/$defs/Two",
            },
        },
        "default": "#/$defs/MustRemainLiteral",
        "metadata": {"mapping": {"literal": "#/$defs/AlsoLiteral"}},
    }


@pytest.mark.parametrize("target", (None, 1, "#/unsupported/Target"))
def test_schema_reference_rewrite_rejects_invalid_discriminator_mapping_targets(
    target: object,
) -> None:
    with pytest.raises(GeneratorError, match="schema reference"):
        contract_generator_common._rewrite_local_refs(
            {
                "propertyName": "kind",
                "mapping": {"sample": target},
            },
            model_pointer="#/models/example.Model",
        )


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
def test_check_rejects_parent_swap_after_clean_inventory_without_mutation(
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
    replacement_output = replacement / generator.OUTPUT_PATH.name
    rendered = generator.render()
    output.write_bytes(rendered)
    output.chmod(0o600)
    replacement_output.write_bytes(rendered)
    replacement_output.chmod(0o600)
    (replacement / "extra.generated").write_bytes(b"unexpected\n")
    monkeypatch.setattr(generator, "OUTPUT_PATH", output)
    old_before = _tree_snapshot(parent)
    replacement_before = _tree_snapshot(replacement)
    original_snapshot = contract_generator_common._owned_snapshot
    swapped = False

    def swap_after_inventory(
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
        if not allow_missing and not swapped:
            parent.rename(old_tree)
            replacement.rename(parent)
            swapped = True
        return result

    monkeypatch.setattr(contract_generator_common, "_owned_snapshot", swap_after_inventory)
    assert generator.main(["--check"]) == 1
    assert swapped
    assert _tree_snapshot(parent) == replacement_before
    assert _tree_snapshot(old_tree) == old_before


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


DIRECTORY_NAMES = ("a.json", "b.md")


def _directory_render() -> dict[str, bytes]:
    return {"a.json": b'{"generation":"current"}\n', "b.md": b"# Current\n"}


def _alternate_directory_render() -> dict[str, bytes]:
    return {"a.json": b'{"generation":"alternate"}\n', "b.md": b"# Alternate\n"}


def _run_directory_generator(
    output: Path,
    arguments: Sequence[str],
    renderer: Callable[[], Mapping[str, bytes]] = _directory_render,
) -> int:
    return contract_generator_common.run_directory_generator(
        output_directory=output,
        expected_names=DIRECTORY_NAMES,
        renderer=renderer,
        argv=arguments,
    )


def _transaction_path(output: Path) -> Path:
    return output.parent / f".{output.name}.transaction"


def _python_environment() -> dict[str, str]:
    return {
        **os.environ,
        "PYTHONHASHSEED": "1",
        "PYTHONPATH": os.pathsep.join((str(ROOT / "packages/contracts/src"), str(ROOT))),
    }


def _writer_source(output: Path, *, target: str | None, loops: int = 1) -> str:
    checkpoint = (
        "def checkpoint(name):\n"
        f"    if name == {target!r}:\n"
        "        os._exit(73)\n"
        "common._transaction_checkpoint = checkpoint\n"
        if target is not None
        else ""
    )
    return (
        "import os\n"
        "from pathlib import Path\n"
        "from scripts import contract_generator_common as common\n"
        f"output = Path({str(output)!r})\n"
        f"names = {DIRECTORY_NAMES!r}\n"
        f"{checkpoint}"
        f"for index in range({loops}):\n"
        "    raw = str(index % 2).encode('ascii')\n"
        "    def render(raw=raw):\n"
        "        return {'a.json': b'{\"generation\":' + raw + b'}\\n', "
        "'b.md': b'# ' + raw + b'\\n'}\n"
        "    if common.run_directory_generator(output_directory=output, "
        "expected_names=names, renderer=render, argv=['--write']) != 0:\n"
        "        raise SystemExit(91)\n"
    )


def _crash_writer(output: Path, target: str) -> subprocess.CompletedProcess[bytes]:
    source = (
        "import os\n"
        "from pathlib import Path\n"
        "from scripts import contract_generator_common as common\n"
        f"output = Path({str(output)!r})\n"
        f"rendered = {_directory_render()!r}\n"
        "def render():\n"
        "    return rendered\n"
        "def checkpoint(name):\n"
        f"    if name == {target!r}:\n"
        "        os._exit(73)\n"
        "common._transaction_checkpoint = checkpoint\n"
        "raise SystemExit(common.run_directory_generator(output_directory=output, "
        f"expected_names={DIRECTORY_NAMES!r}, renderer=render, argv=['--write']))\n"
    )
    return subprocess.run(
        [sys.executable, "-c", source],
        cwd=ROOT,
        env=_python_environment(),
        check=False,
        capture_output=True,
    )


def _wait_for_path(path: Path, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 10
    while not path.exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    assert path.exists(), process.communicate(timeout=1)


def test_generated_directory_write_check_snapshot_and_exact_inventory(
    tmp_path: Path,
) -> None:
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    assert tuple(sorted(path.name for path in output.iterdir())) == DIRECTORY_NAMES
    assert {path.name: path.read_bytes() for path in output.iterdir()} == _directory_render()
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in output.iterdir())
    assert not _transaction_path(output).exists()

    before = _tree_snapshot(tmp_path)
    assert _run_directory_generator(output, ["--check"]) == 0
    assert _tree_snapshot(tmp_path) == before
    with contract_generator_common.open_generated_directory_snapshot(
        output,
        DIRECTORY_NAMES,
    ) as snapshot:
        assert snapshot.names == DIRECTORY_NAMES
        assert {name: snapshot.read_bytes(name) for name in snapshot.names} == _directory_render()
    with pytest.raises(GeneratorError, match="closed"):
        snapshot.read_bytes("a.json")


def test_snapshot_close_failure_still_releases_parent_lock_and_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    snapshot = contract_generator_common.open_generated_directory_snapshot(
        output,
        DIRECTORY_NAMES,
    )
    directory_fd = snapshot._directory.descriptor
    parent_fd = snapshot._parent.descriptor
    real_close = os.close
    failed = False

    def consume_directory_close_then_fail(descriptor: int) -> None:
        nonlocal failed
        if descriptor == directory_fd and not failed:
            failed = True
            real_close(descriptor)
            raise OSError(errno.EIO, "synthetic snapshot close failure")
        real_close(descriptor)

    monkeypatch.setattr(os, "close", consume_directory_close_then_fail)
    with pytest.raises(OSError, match="synthetic snapshot close failure") as close_error:
        snapshot.close()
    assert close_error.value.errno == errno.EIO
    assert failed
    with pytest.raises(OSError) as parent_error:
        os.fstat(parent_fd)
    assert parent_error.value.errno == errno.EBADF
    with pytest.raises(OSError) as directory_error:
        os.fstat(directory_fd)
    assert directory_error.value.errno == errno.EBADF

    replacement_fd = os.open(output, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    if replacement_fd != directory_fd:
        os.dup2(replacement_fd, directory_fd)
        real_close(replacement_fd)
    snapshot.close()
    os.fstat(directory_fd)
    real_close(directory_fd)
    snapshot.close()


def test_snapshot_close_preserves_primary_error_across_parent_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    snapshot = contract_generator_common.open_generated_directory_snapshot(
        output,
        DIRECTORY_NAMES,
    )
    directory_fd = snapshot._directory.descriptor
    parent_fd = snapshot._parent.descriptor
    real_close = os.close
    real_flock = fcntl.flock
    failed_directory_close = False

    def consume_directory_close_then_fail(descriptor: int) -> None:
        nonlocal failed_directory_close
        if descriptor == directory_fd and not failed_directory_close:
            failed_directory_close = True
            real_close(descriptor)
            raise OSError(errno.EIO, "synthetic snapshot close failure")
        real_close(descriptor)

    def fail_parent_unlock(descriptor: int, operation: int) -> None:
        if descriptor == parent_fd and operation == fcntl.LOCK_UN:
            raise OSError(errno.EPERM, "synthetic parent unlock failure")
        real_flock(descriptor, operation)

    monkeypatch.setattr(os, "close", consume_directory_close_then_fail)
    monkeypatch.setattr(fcntl, "flock", fail_parent_unlock)
    with pytest.raises(OSError, match="synthetic snapshot close failure") as close_error:
        snapshot.close()
    assert close_error.value.errno == errno.EIO
    assert any("synthetic parent unlock failure" in note for note in close_error.value.__notes__)
    with pytest.raises(OSError) as parent_error:
        os.fstat(parent_fd)
    assert parent_error.value.errno == errno.EBADF
    with pytest.raises(OSError) as directory_error:
        os.fstat(directory_fd)
    assert directory_error.value.errno == errno.EBADF
    snapshot.close()


def test_snapshot_context_preserves_body_error_when_cleanup_also_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    snapshot = contract_generator_common.open_generated_directory_snapshot(
        output,
        DIRECTORY_NAMES,
    )
    directory_fd = snapshot._directory.descriptor
    parent_fd = snapshot._parent.descriptor
    real_close = os.close
    failed = False

    def consume_directory_close_then_fail(descriptor: int) -> None:
        nonlocal failed
        real_close(descriptor)
        if descriptor == directory_fd and not failed:
            failed = True
            raise OSError(errno.EIO, "synthetic snapshot close failure")

    monkeypatch.setattr(os, "close", consume_directory_close_then_fail)
    with pytest.raises(ValueError, match="synthetic body failure") as body_error, snapshot:
        raise ValueError("synthetic body failure")
    assert any("synthetic snapshot close failure" in note for note in body_error.value.__notes__)
    for descriptor in (directory_fd, parent_fd):
        with pytest.raises(OSError) as closed_error:
            os.fstat(descriptor)
        assert closed_error.value.errno == errno.EBADF


def test_snapshot_construction_preserves_primary_error_and_disposes_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    real_open = contract_generator_common._open_generated_directory
    real_lock = contract_generator_common._lock_output_parent
    real_close = os.close
    directory_fd: int | None = None
    parent_fd: int | None = None
    failed = False

    def capture_open(
        bound_parent_fd: int,
        name: str,
        *,
        private: bool,
    ) -> contract_generator_common.GeneratedDirectoryHandle:
        nonlocal directory_fd
        handle = real_open(bound_parent_fd, name, private=private)
        directory_fd = handle.descriptor
        return handle

    def capture_lock(
        parent: contract_generator_common.OutputParent,
        *,
        exclusive: bool,
    ) -> None:
        nonlocal parent_fd
        real_lock(parent, exclusive=exclusive)
        parent_fd = parent.descriptor

    def fail_snapshot(*args: object, **kwargs: object) -> NoReturn:
        del args, kwargs
        raise ValueError("synthetic snapshot construction failure")

    def consume_directory_close_then_fail(descriptor: int) -> None:
        nonlocal failed
        real_close(descriptor)
        if descriptor == directory_fd and not failed:
            failed = True
            raise OSError(errno.EIO, "synthetic directory cleanup failure")

    monkeypatch.setattr(contract_generator_common, "_open_generated_directory", capture_open)
    monkeypatch.setattr(contract_generator_common, "_lock_output_parent", capture_lock)
    monkeypatch.setattr(contract_generator_common, "_snapshot_generated_directory", fail_snapshot)
    monkeypatch.setattr(os, "close", consume_directory_close_then_fail)
    with pytest.raises(ValueError, match="synthetic snapshot construction failure") as primary:
        contract_generator_common.open_generated_directory_snapshot(output, DIRECTORY_NAMES)
    assert any("synthetic directory cleanup failure" in note for note in primary.value.__notes__)
    assert directory_fd is not None
    assert parent_fd is not None
    for descriptor in (directory_fd, parent_fd):
        with pytest.raises(OSError) as closed_error:
            os.fstat(descriptor)
        assert closed_error.value.errno == errno.EBADF


def test_safe_git_checkout_modes_are_accepted_and_replaced(tmp_path: Path) -> None:
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    output.chmod(0o755)
    for path in output.iterdir():
        path.chmod(0o644)
    assert _run_directory_generator(output, ["--check"]) == 0
    assert _run_directory_generator(output, ["--write"], _alternate_directory_render) == 0
    assert {path.name: path.read_bytes() for path in output.iterdir()} == (
        _alternate_directory_render()
    )


def test_fresh_git_checkout_modes_are_accepted(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    output = source / "fixtures/v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    commands = (
        ("init", "-q"),
        ("config", "user.email", "fixture@example.invalid"),
        ("config", "user.name", "Fixture Test"),
        ("add", "fixtures/v1"),
        ("commit", "-qm", "fixture"),
    )
    for arguments in commands:
        subprocess.run(
            ["git", *arguments],
            cwd=source,
            check=True,
            capture_output=True,
        )
    checkout = tmp_path / "checkout"
    previous_umask = os.umask(0o022)
    try:
        subprocess.run(
            ["git", "clone", "-q", str(source), str(checkout)],
            check=True,
            capture_output=True,
        )
    finally:
        os.umask(previous_umask)
    checked_output = checkout / "fixtures/v1"
    assert stat.S_IMODE(checked_output.stat().st_mode) == 0o755
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o644 for path in checked_output.iterdir())
    assert _run_directory_generator(checked_output, ["--check"]) == 0


@pytest.mark.parametrize(
    ("target", "mode"),
    (("file", 0o744), ("file", 0o662), ("directory", 0o777)),
)
def test_unsafe_published_modes_fail_closed_without_mutation(
    target: str,
    mode: int,
    tmp_path: Path,
) -> None:
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    (output / "a.json" if target == "file" else output).chmod(mode)
    before = _tree_snapshot(tmp_path)
    assert _run_directory_generator(output, ["--check"]) == 1
    assert _run_directory_generator(output, ["--write"]) == 1
    assert _tree_snapshot(tmp_path) == before


def test_wrong_owner_policy_fails_closed_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    before = _tree_snapshot(tmp_path)
    real_euid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real_euid + 1)
    assert _run_directory_generator(output, ["--check"]) == 1
    assert _run_directory_generator(output, ["--write"]) == 1
    assert _tree_snapshot(tmp_path) == before


@pytest.mark.parametrize(
    "hostile_kind",
    ("extra", "missing", "symlink", "hardlink", "fifo"),
)
def test_generated_directory_rejects_hostile_entry_without_mutation(
    hostile_kind: str,
    tmp_path: Path,
) -> None:
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    target = tmp_path / "outside"
    target.write_bytes(b"outside\n")
    hostile = output / ("extra" if hostile_kind == "extra" else "a.json")
    if hostile_kind != "extra":
        hostile.unlink()
    if hostile_kind == "extra":
        hostile.write_bytes(b"unexpected\n")
    elif hostile_kind == "missing":
        pass
    elif hostile_kind == "symlink":
        hostile.symlink_to(target)
    elif hostile_kind == "hardlink":
        os.link(target, hostile)
    else:
        os.mkfifo(hostile, mode=0o600)
    before = _tree_snapshot(tmp_path)
    assert _run_directory_generator(output, ["--check"]) == 1
    assert _run_directory_generator(output, ["--write"]) == 1
    assert _tree_snapshot(tmp_path) == before
    assert target.read_bytes() == b"outside\n"


def test_generated_directory_rejects_symlinked_output_without_mutation(
    tmp_path: Path,
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    output = tmp_path / "v1"
    output.symlink_to(real, target_is_directory=True)
    before = _tree_snapshot(tmp_path)
    assert _run_directory_generator(output, ["--check"]) == 1
    assert _run_directory_generator(output, ["--write"]) == 1
    assert _tree_snapshot(tmp_path) == before


@pytest.mark.parametrize("root_kind", ("file", "fifo"))
def test_generated_directory_rejects_nondirectory_output_without_mutation(
    root_kind: str,
    tmp_path: Path,
) -> None:
    output = tmp_path / "v1"
    if root_kind == "file":
        output.write_bytes(b"not a directory\n")
    else:
        os.mkfifo(output, mode=0o600)
    before = _tree_snapshot(tmp_path)
    assert _run_directory_generator(output, ["--check"]) == 1
    assert _run_directory_generator(output, ["--write"]) == 1
    assert _tree_snapshot(tmp_path) == before


def test_generated_directory_rejects_nondeterminism_before_path_touch(
    tmp_path: Path,
) -> None:
    output = tmp_path / "missing" / "v1"
    calls = 0

    def render() -> dict[str, bytes]:
        nonlocal calls
        calls += 1
        return {"a.json": f"{calls}\n".encode(), "b.md": b"same\n"}

    before = _tree_snapshot(tmp_path)
    assert _run_directory_generator(output, ["--write"], render) == 1
    assert calls == 2
    assert _tree_snapshot(tmp_path) == before


def test_writer_parent_name_swap_cleans_bound_pre_state_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "parent"
    parent.mkdir()
    output = parent / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    parent_before = _tree_snapshot(parent)
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "sentinel").write_bytes(b"replacement\n")
    replacement_before = _tree_snapshot(replacement)
    old_parent = tmp_path / "old-parent"
    swapped = False

    def swap_at_prepared(name: str) -> None:
        nonlocal swapped
        if name == "prepared" and not swapped:
            parent.rename(old_parent)
            replacement.rename(parent)
            swapped = True

    monkeypatch.setattr(
        contract_generator_common,
        "_transaction_checkpoint",
        swap_at_prepared,
    )
    assert _run_directory_generator(output, ["--write"], _alternate_directory_render) == 1
    assert swapped
    assert _tree_snapshot(old_parent) == parent_before
    assert _tree_snapshot(parent) == replacement_before


def test_snapshot_parent_name_swap_is_nonmutating_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "parent"
    parent.mkdir()
    output = parent / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    parent_before = _tree_snapshot(parent)
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "sentinel").write_bytes(b"replacement\n")
    replacement_before = _tree_snapshot(replacement)
    old_parent = tmp_path / "old-parent"
    real_snapshot = contract_generator_common._snapshot_generated_directory
    swapped = False

    def swap_after_snapshot(
        handle: contract_generator_common.GeneratedDirectoryHandle,
        expected_names: tuple[str, ...],
        *,
        require_exact: bool,
        private: bool,
    ) -> tuple[contract_generator_common.GeneratedDirectoryEntry, ...]:
        nonlocal swapped
        result = real_snapshot(
            handle,
            expected_names,
            require_exact=require_exact,
            private=private,
        )
        if not swapped:
            parent.rename(old_parent)
            replacement.rename(parent)
            swapped = True
        return result

    monkeypatch.setattr(
        contract_generator_common,
        "_snapshot_generated_directory",
        swap_after_snapshot,
    )
    assert _run_directory_generator(output, ["--check"]) == 1
    assert swapped
    assert _tree_snapshot(old_parent) == parent_before
    assert _tree_snapshot(parent) == replacement_before


def test_parent_directory_fd_is_the_only_lock_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "v1"
    real_flock = fcntl.flock
    locked_modes: list[int] = []

    def record_flock(descriptor: int, operation: int) -> None:
        if operation != fcntl.LOCK_UN:
            locked_modes.append(os.fstat(descriptor).st_mode)
        real_flock(descriptor, operation)

    monkeypatch.setattr(fcntl, "flock", record_flock)
    assert _run_directory_generator(output, ["--write"]) == 0
    assert _run_directory_generator(output, ["--check"]) == 0
    assert locked_modes and all(stat.S_ISDIR(mode) for mode in locked_modes)
    assert not any("lock" in path.name for path in tmp_path.rglob("*"))


def test_failed_exclusive_lock_does_not_reconcile_pending_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "v1"
    crashed = _crash_writer(output, "prepared")
    assert crashed.returncode == 73
    assert _transaction_path(output).is_dir()
    before = _tree_snapshot(tmp_path)
    real_flock = fcntl.flock

    def fail_exclusive_lock(descriptor: int, operation: int) -> None:
        if operation == fcntl.LOCK_EX:
            raise OSError(errno.EIO, "synthetic exclusive lock failure")
        real_flock(descriptor, operation)

    monkeypatch.setattr(fcntl, "flock", fail_exclusive_lock)
    assert _run_directory_generator(output, ["--write"]) == 1
    assert _tree_snapshot(tmp_path) == before
    assert _transaction_path(output).is_dir()


def test_restrictive_umask_normalizes_new_output_parents(
    tmp_path: Path,
) -> None:
    output = tmp_path / "fresh/fixtures/v1"
    previous_umask = os.umask(0o177)
    try:
        assert _run_directory_generator(output, ["--write"]) == 0
    finally:
        os.umask(previous_umask)
    assert stat.S_IMODE((tmp_path / "fresh").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "fresh/fixtures").stat().st_mode) == 0o700
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in output.iterdir())
    assert not _transaction_path(output).exists()
    assert _run_directory_generator(output, ["--write"], _alternate_directory_render) == 0


def test_restrictive_umask_normalizes_transaction_and_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "v1"
    inspected = False

    def inspect_prepared_modes(name: str) -> None:
        nonlocal inspected
        if name != "prepared":
            return
        transaction = _transaction_path(output)
        stage = transaction / "stage"
        assert stat.S_IMODE(transaction.stat().st_mode) == 0o700
        assert stat.S_IMODE(stage.stat().st_mode) == 0o700
        assert stat.S_IMODE((transaction / "intent.json").stat().st_mode) == 0o600
        assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in stage.iterdir())
        inspected = True

    monkeypatch.setattr(
        contract_generator_common,
        "_transaction_checkpoint",
        inspect_prepared_modes,
    )
    previous_umask = os.umask(0o177)
    try:
        assert _run_directory_generator(output, ["--write"]) == 0
    finally:
        os.umask(previous_umask)
    assert inspected
    assert not _transaction_path(output).exists()
    assert _run_directory_generator(output, ["--write"], _alternate_directory_render) == 0


def test_owner_read_removing_umask_is_rejected_before_output_path_touch(
    tmp_path: Path,
) -> None:
    output = tmp_path / "missing/fixtures/v1"
    previous_umask = os.umask(0o777)
    try:
        assert _run_directory_generator(output, ["--write"]) == 1
    finally:
        os.umask(previous_umask)
    try:
        assert not output.parents[1].exists()
    finally:
        if output.parents[1].exists():
            output.parents[1].chmod(0o700)
            output.parents[1].rmdir()


def test_private_directory_umask_probe_uses_each_bound_creation_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "fresh/fixtures/v1"
    real_probe = contract_generator_common._require_supported_private_directory_umask
    inspected: list[tuple[int, int]] = []

    def inspect_bound_parent(parent_fd: int) -> None:
        metadata = os.fstat(parent_fd)
        assert stat.S_ISDIR(metadata.st_mode)
        assert metadata.st_uid == os.geteuid()
        assert not stat.S_IMODE(metadata.st_mode) & 0o022
        inspected.append((metadata.st_dev, metadata.st_ino))
        real_probe(parent_fd)

    def reject_ambient_probe(*args: object, **kwargs: object) -> NoReturn:
        del args, kwargs
        raise AssertionError("ambient temporary directory must not prove output-parent umask")

    monkeypatch.setattr(
        contract_generator_common,
        "_require_supported_private_directory_umask",
        inspect_bound_parent,
    )
    monkeypatch.setattr(
        contract_generator_common,
        "TemporaryFile",
        reject_ambient_probe,
        raising=False,
    )
    assert _run_directory_generator(output, ["--write"]) == 0
    assert len(inspected) == 4
    assert len(set(inspected)) == 4


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux default ACL regression")
def test_linux_ambient_default_acl_cannot_mask_unsafe_output_parent_umask(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ambient = tmp_path / "ambient"
    output_parent = tmp_path / "output-parent"
    ambient.mkdir(mode=0o700)
    output_parent.mkdir(mode=0o700)
    default_acl = struct.pack("<I", 2) + b"".join(
        struct.pack("<HHI", tag, permissions, 0xFFFFFFFF)
        for tag, permissions in ((0x01, 0o7), (0x04, 0), (0x20, 0))
    )
    setter = getattr(os, "setxattr", None)
    if not callable(setter):
        pytest.skip("platform has no extended-attribute API")
    set_extended_attribute = cast(Callable[[Path, bytes, bytes], None], setter)
    try:
        set_extended_attribute(ambient, b"system.posix_acl_default", default_acl)
    except OSError as error:
        pytest.skip(f"filesystem cannot establish a Linux default ACL: {error}")

    validation_name = "acl-umask-validation"
    validation_fd: int | None = None
    ambient_fd = os.open(ambient, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    inherited_mode = 0
    previous_umask = os.umask(0o777)
    try:
        validation_fd = os.open(
            validation_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=ambient_fd,
        )
        inherited_mode = stat.S_IMODE(os.fstat(validation_fd).st_mode)
    finally:
        os.umask(previous_umask)
        if validation_fd is not None:
            os.close(validation_fd)
        os.close(ambient_fd)
        with suppress(FileNotFoundError):
            (ambient / validation_name).unlink()
    if not inherited_mode & stat.S_IRUSR:
        pytest.skip("filesystem default ACL did not override the process umask")

    output = output_parent / "missing/v1"
    monkeypatch.setattr(
        contract_generator_common, "gettempdir", lambda: str(ambient), raising=False
    )
    previous_umask = os.umask(0o777)
    try:
        assert _run_directory_generator(output, ["--write"]) == 1
    finally:
        os.umask(previous_umask)
        if output.parent.exists():
            output.parent.chmod(0o700)
            output.parent.rmdir()
    assert not output.parent.exists()


def test_linux_acl_policy_rejects_non_posix_and_unknown_filesystem_surfaces() -> None:
    for magic in (0xEF53, 0x58465342, 0x9123683E, 0x01021994, 0x794C7630, 0xF2F52010):
        contract_generator_common._require_supported_linux_acl_filesystem_magic(magic)
    for magic in (0x6969, 0xFF534D42, 0x2FC12FC1, 0xDEADBEEF):
        with pytest.raises(GeneratorError, match="unsupported Linux filesystem ACL semantics"):
            contract_generator_common._require_supported_linux_acl_filesystem_magic(magic)

    for attribute in (b"system.posix_acl_access", b"system.posix_acl_default"):
        assert contract_generator_common._classify_linux_acl_attribute(attribute) == "posix"
    assert contract_generator_common._classify_linux_acl_attribute(b"security.selinux") == "other"
    for attribute in (
        b"system.nfs4_acl",
        b"system.cifs_acl",
        b"system.richacl",
        b"security.NTACL",
        b"trusted.SGI_ACL_FILE",
    ):
        with pytest.raises(GeneratorError, match="unsupported Linux discretionary ACL"):
            contract_generator_common._classify_linux_acl_attribute(attribute)

    class UnsupportedXattrLister:
        argtypes: object = None
        restype: object = None

        def __call__(self, descriptor: int, names: object, size: int) -> int:
            del descriptor, names, size
            ctypes.set_errno(errno.EOPNOTSUPP)
            return -1

    class UnsupportedXattrLibrary:
        flistxattr = UnsupportedXattrLister()

    with pytest.raises(GeneratorError, match="ACL inspection failed"):
        contract_generator_common._linux_extended_attribute_names(
            cast(ctypes.CDLL, UnsupportedXattrLibrary()),
            42,
        )


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux POSIX ACL regression")
def test_linux_posix_acl_creation_parent_fails_closed_without_mutation(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "acl-parent"
    parent.mkdir(mode=0o700)
    default_acl = struct.pack("<I", 2) + b"".join(
        struct.pack("<HHI", tag, permissions, 0xFFFFFFFF)
        for tag, permissions in ((0x01, 0o7), (0x04, 0), (0x20, 0))
    )
    setter = getattr(os, "setxattr", None)
    if not callable(setter):
        pytest.skip("platform has no extended-attribute API")
    set_extended_attribute = cast(Callable[[Path, bytes, bytes], None], setter)
    getter = getattr(os, "getxattr", None)
    if not callable(getter):
        pytest.skip("platform has no extended-attribute read API")
    get_extended_attribute = cast(Callable[[Path, bytes], bytes], getter)
    try:
        set_extended_attribute(parent, b"system.posix_acl_default", default_acl)
    except OSError as error:
        pytest.skip(f"filesystem cannot establish a Linux default ACL: {error}")

    output = parent / "v1"
    before = _tree_snapshot(parent)
    acl_before = get_extended_attribute(parent, b"system.posix_acl_default")
    assert _run_directory_generator(output, ["--write"]) == 1
    assert _tree_snapshot(parent) == before
    assert get_extended_attribute(parent, b"system.posix_acl_default") == acl_before


def test_created_private_directory_name_swap_fails_without_touching_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "fresh/v1"
    created = output.parent
    displaced = tmp_path / "displaced"
    real_fchmod = os.fchmod
    swapped = False

    def swap_during_normalization(descriptor: int, mode: int) -> None:
        nonlocal swapped
        if not swapped and created.exists():
            named = created.stat(follow_symlinks=False)
            opened = os.fstat(descriptor)
            if (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino):
                created.rename(displaced)
                created.mkdir(mode=0o700)
                (created / "sentinel").write_bytes(b"replacement\n")
                swapped = True
        real_fchmod(descriptor, mode)

    monkeypatch.setattr(os, "fchmod", swap_during_normalization)
    assert _run_directory_generator(output, ["--write"]) == 1
    assert swapped
    assert (created / "sentinel").read_bytes() == b"replacement\n"
    assert stat.S_IMODE(created.stat().st_mode) == 0o700
    assert stat.S_IMODE(displaced.stat().st_mode) == 0o700
    assert not output.exists()


def test_created_private_directory_rejects_unsafe_replacement_before_first_stat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "fresh/v1"
    created = output.parent
    displaced = tmp_path / "displaced"
    real_mkdir = os.mkdir
    swapped = False

    def swap_before_first_stat(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal swapped
        real_mkdir(path, mode, dir_fd=dir_fd)
        if not swapped and path == "fresh":
            created.rename(displaced)
            real_mkdir(created, 0o700)
            created.chmod(0o777)
            (created / "sentinel").write_bytes(b"unsafe replacement\n")
            swapped = True

    monkeypatch.setattr(os, "mkdir", swap_before_first_stat)
    assert _run_directory_generator(output, ["--write"]) == 1
    assert swapped
    assert (created / "sentinel").read_bytes() == b"unsafe replacement\n"
    assert stat.S_IMODE(created.stat().st_mode) == 0o777
    assert displaced.is_dir()
    assert not output.exists()


def test_created_private_directory_preserves_validation_error_when_close_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent_fd = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    os.mkdir("created", mode=0o700, dir_fd=parent_fd)
    real_open = os.open
    real_close = os.close
    created_fd: int | None = None

    def capture_created_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal created_fd
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == "created":
            created_fd = descriptor
        return descriptor

    def fail_validation(descriptor: int) -> bool:
        if descriptor == created_fd:
            raise ValueError("synthetic created-directory validation failure")
        return False

    def consume_created_close_then_fail(descriptor: int) -> None:
        real_close(descriptor)
        if descriptor == created_fd:
            raise OSError(errno.EIO, "synthetic created-directory close failure")

    monkeypatch.setattr(os, "open", capture_created_open)
    monkeypatch.setattr(contract_generator_common, "_directory_has_extended_acl", fail_validation)
    monkeypatch.setattr(os, "close", consume_created_close_then_fail)
    try:
        with pytest.raises(
            ValueError,
            match="synthetic created-directory validation failure",
        ) as primary:
            contract_generator_common._open_created_private_directory(parent_fd, "created")
        assert any(
            "synthetic created-directory close failure" in note for note in primary.value.__notes__
        )
    finally:
        real_close(parent_fd)


def test_directory_creation_rejects_group_or_world_writable_parent_without_mutation(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "shared"
    parent.mkdir(mode=0o700)
    parent.chmod(0o777)
    output = parent / "v1"
    before = _tree_snapshot(parent)
    assert _run_directory_generator(output, ["--write"]) == 1
    assert _tree_snapshot(parent) == before


def test_directory_creation_rejects_acl_signaled_parent_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "acl-parent"
    parent.mkdir(mode=0o700)
    output = parent / "v1"
    parent_identity = (parent.stat().st_dev, parent.stat().st_ino)
    before = _tree_snapshot(parent)

    def has_extended_acl(descriptor: int) -> bool:
        metadata = os.fstat(descriptor)
        return (metadata.st_dev, metadata.st_ino) == parent_identity

    monkeypatch.setattr(
        contract_generator_common,
        "_directory_has_extended_acl",
        has_extended_acl,
        raising=False,
    )
    assert _run_directory_generator(output, ["--write"]) == 1
    assert _tree_snapshot(parent) == before


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin extended ACL regression")
def test_darwin_inherited_extended_acl_parent_fails_closed_without_mutation(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "acl-parent"
    parent.mkdir(mode=0o700)
    acl = "everyone allow add_file,add_subdirectory,delete_child,file_inherit,directory_inherit"
    subprocess.run(["/bin/chmod", "+a", acl, str(parent)], check=True, capture_output=True)
    output = parent / "v1"
    before = _tree_snapshot(parent)
    acl_before = subprocess.run(
        ["/bin/ls", "-lde", str(parent)],
        check=True,
        capture_output=True,
    ).stdout
    try:
        assert _run_directory_generator(output, ["--write"]) == 1
        assert _tree_snapshot(parent) == before
        assert (
            subprocess.run(
                ["/bin/ls", "-lde", str(parent)],
                check=True,
                capture_output=True,
            ).stdout
            == acl_before
        )
    finally:
        subprocess.run(["/bin/chmod", "-RN", str(parent)], check=True, capture_output=True)


def test_directory_writer_declares_same_euid_and_stable_umask_trust_boundary() -> None:
    contract = contract_generator_common.run_directory_generator.__doc__
    assert contract is not None
    assert "stable process umask" in contract
    assert "Same-EUID local writers are trusted to honor the parent flock" in contract


def test_private_transaction_modes_are_exact_at_prepared_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "v1"
    inspected = False

    def inspect_then_interrupt(name: str) -> None:
        nonlocal inspected
        if name != "prepared" or inspected:
            return
        transaction = _transaction_path(output)
        assert stat.S_IMODE(transaction.stat().st_mode) == 0o700
        assert stat.S_IMODE((transaction / "stage").stat().st_mode) == 0o700
        assert stat.S_IMODE((transaction / "intent.json").stat().st_mode) == 0o600
        assert all(
            stat.S_IMODE(path.stat().st_mode) == 0o600 for path in (transaction / "stage").iterdir()
        )
        inspected = True
        raise KeyboardInterrupt

    monkeypatch.setattr(
        contract_generator_common,
        "_transaction_checkpoint",
        inspect_then_interrupt,
    )
    with pytest.raises(KeyboardInterrupt):
        _run_directory_generator(output, ["--write"])
    assert inspected
    assert not output.exists()
    assert not _transaction_path(output).exists()


def test_pre_recovery_preserves_exact_baseline_modes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    output.chmod(0o755)
    for path in output.iterdir():
        path.chmod(0o644)
    before = _tree_snapshot(output)
    raised = False

    def interrupt_once(name: str) -> None:
        nonlocal raised
        if name == "prepared" and not raised:
            raised = True
            raise KeyboardInterrupt

    monkeypatch.setattr(
        contract_generator_common,
        "_transaction_checkpoint",
        interrupt_once,
    )
    with pytest.raises(KeyboardInterrupt):
        _run_directory_generator(output, ["--write"], _alternate_directory_render)
    assert _tree_snapshot(output) == before
    assert not _transaction_path(output).exists()


@pytest.mark.parametrize(
    "checkpoint",
    (
        "transaction-created",
        "stage-created",
        "stage-file-opened",
        "stage-entry",
        "intent-file-opened",
        "intent-temporary",
        "prepared",
        "committed",
        "cleanup-entry",
        "cleanup-complete",
    ),
)
def test_baseexception_reconciles_checkpoint_and_reraises(
    checkpoint: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    baseline = {path.name: path.read_bytes() for path in output.iterdir()}
    raised = False

    def interrupt_once(name: str) -> None:
        nonlocal raised
        if name == checkpoint and not raised:
            raised = True
            raise KeyboardInterrupt

    monkeypatch.setattr(
        contract_generator_common,
        "_transaction_checkpoint",
        interrupt_once,
    )
    with pytest.raises(KeyboardInterrupt):
        _run_directory_generator(output, ["--write"], _alternate_directory_render)
    expected = (
        baseline
        if checkpoint
        in {
            "transaction-created",
            "stage-created",
            "stage-file-opened",
            "stage-entry",
            "intent-file-opened",
            "intent-temporary",
            "prepared",
        }
        else _alternate_directory_render()
    )
    assert {path.name: path.read_bytes() for path in output.iterdir()} == expected
    assert not _transaction_path(output).exists()


@pytest.mark.parametrize(
    "checkpoint",
    (
        "transaction-created",
        "stage-created",
        "stage-file-opened",
        "stage-entry",
        "intent-file-opened",
        "intent-temporary",
        "prepared",
        "committed",
        "cleanup-entry",
        "cleanup-complete",
    ),
)
def test_process_crash_is_reconciled_by_next_write(
    checkpoint: str,
    tmp_path: Path,
) -> None:
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    crashed = _crash_writer(output, checkpoint)
    assert crashed.returncode == 73
    assert _transaction_path(output).is_dir() is (checkpoint != "cleanup-complete")
    assert _run_directory_generator(output, ["--write"]) == 0
    assert {path.name: path.read_bytes() for path in output.iterdir()} == _directory_render()
    assert not _transaction_path(output).exists()


def test_post_recovery_cleans_exchanged_safe_git_modes(tmp_path: Path) -> None:
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    output.chmod(0o755)
    for path in output.iterdir():
        path.chmod(0o644)
    assert _crash_writer(output, "committed").returncode == 73
    assert _run_directory_generator(output, ["--write"]) == 0
    assert not _transaction_path(output).exists()
    assert {path.name: path.read_bytes() for path in output.iterdir()} == _directory_render()


def test_check_with_pending_recovery_is_nonmutating(tmp_path: Path) -> None:
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    assert _crash_writer(output, "prepared").returncode == 73
    before = _tree_snapshot(tmp_path)
    assert _run_directory_generator(output, ["--check"]) == 1
    assert _tree_snapshot(tmp_path) == before
    assert _run_directory_generator(output, ["--write"]) == 0
    assert not _transaction_path(output).exists()


@pytest.mark.parametrize("tamper", ("intent", "stage", "intent-temporary"))
def test_ambiguous_transaction_is_retained_without_rename_or_delete(
    tamper: str,
    tmp_path: Path,
) -> None:
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    crash_point = "intent-temporary" if tamper == "intent-temporary" else "prepared"
    assert _crash_writer(output, crash_point).returncode == 73
    transaction = _transaction_path(output)
    targets = {
        "intent": "intent.json",
        "intent-temporary": ".intent.tmp",
        "stage": "stage/a.json",
    }
    target = transaction / targets[tamper]
    target.write_bytes(b"tampered\n")
    target.chmod(0o600)
    before = _tree_snapshot(tmp_path)
    assert _run_directory_generator(output, ["--check"]) == 1
    assert _run_directory_generator(output, ["--write"]) == 1
    assert _tree_snapshot(tmp_path) == before


def test_snapshot_reader_blocks_writer_and_sees_one_generation(tmp_path: Path) -> None:
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    ready = tmp_path / "reader-ready"
    release = tmp_path / "reader-release"
    observed = tmp_path / "reader-observed"
    reader_source = (
        "import time\n"
        "from pathlib import Path\n"
        "from scripts.contract_generator_common import open_generated_directory_snapshot\n"
        f"output = Path({str(output)!r})\n"
        f"ready = Path({str(ready)!r})\n"
        f"release = Path({str(release)!r})\n"
        f"observed = Path({str(observed)!r})\n"
        f"with open_generated_directory_snapshot(output, {DIRECTORY_NAMES!r}) as snapshot:\n"
        "    ready.write_text('ready', encoding='utf-8')\n"
        "    while not release.exists():\n"
        "        time.sleep(0.01)\n"
        "    observed.write_bytes(snapshot.read_bytes('a.json'))\n"
    )
    reader = subprocess.Popen(
        [sys.executable, "-c", reader_source],
        cwd=ROOT,
        env=_python_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _wait_for_path(ready, reader)
    writer_source = _writer_source(output, target=None).replace(
        "str(index % 2).encode('ascii')",
        "b'9'",
    )
    writer = subprocess.Popen(
        [sys.executable, "-c", writer_source],
        cwd=ROOT,
        env=_python_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.1)
    assert writer.poll() is None
    release.write_text("release", encoding="utf-8")
    assert reader.communicate(timeout=10) == (b"", b"")
    assert reader.returncode == 0
    assert writer.communicate(timeout=10) == (b"", b"")
    assert writer.returncode == 0
    assert observed.read_bytes() == _directory_render()["a.json"]
    assert (output / "a.json").read_bytes() == b'{"generation":9}\n'


def test_reader_started_at_prepared_boundary_blocks_then_sees_commit(
    tmp_path: Path,
) -> None:
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    prepared = tmp_path / "writer-prepared"
    release = tmp_path / "writer-release"
    observed = tmp_path / "reader-observed"
    writer_source = (
        "import time\n"
        "from pathlib import Path\n"
        "from scripts import contract_generator_common as common\n"
        f"output = Path({str(output)!r})\n"
        f"prepared = Path({str(prepared)!r})\n"
        f"release = Path({str(release)!r})\n"
        f"rendered = {_alternate_directory_render()!r}\n"
        "def render():\n"
        "    return rendered\n"
        "def checkpoint(name):\n"
        "    if name == 'prepared':\n"
        "        prepared.write_text('prepared', encoding='utf-8')\n"
        "        while not release.exists():\n"
        "            time.sleep(0.01)\n"
        "common._transaction_checkpoint = checkpoint\n"
        "raise SystemExit(common.run_directory_generator(output_directory=output, "
        f"expected_names={DIRECTORY_NAMES!r}, renderer=render, argv=['--write']))\n"
    )
    writer = subprocess.Popen(
        [sys.executable, "-c", writer_source],
        cwd=ROOT,
        env=_python_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _wait_for_path(prepared, writer)
    reader_source = (
        "from pathlib import Path\n"
        "from scripts.contract_generator_common import open_generated_directory_snapshot\n"
        f"output = Path({str(output)!r})\n"
        f"observed = Path({str(observed)!r})\n"
        f"with open_generated_directory_snapshot(output, {DIRECTORY_NAMES!r}) as snapshot:\n"
        "    observed.write_bytes(snapshot.read_bytes('a.json'))\n"
    )
    reader = subprocess.Popen(
        [sys.executable, "-c", reader_source],
        cwd=ROOT,
        env=_python_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.1)
    assert reader.poll() is None
    assert not observed.exists()
    release.write_text("release", encoding="utf-8")
    assert writer.communicate(timeout=10) == (b"", b"")
    assert writer.returncode == 0
    assert reader.communicate(timeout=10) == (b"", b"")
    assert reader.returncode == 0
    assert observed.read_bytes() == _alternate_directory_render()["a.json"]


def test_raw_reader_never_observes_missing_output_name_across_real_exchanges(
    tmp_path: Path,
) -> None:
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    writer = subprocess.Popen(
        [sys.executable, "-c", _writer_source(output, target=None, loops=24)],
        cwd=ROOT,
        env=_python_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    observations = 0
    missing = False
    while writer.poll() is None:
        try:
            descriptor = os.open(
                output,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
        except FileNotFoundError:
            missing = True
            break
        else:
            os.close(descriptor)
            observations += 1
    stdout, stderr = writer.communicate(timeout=10)
    assert (writer.returncode, stdout, stderr) == (0, b"", b"")
    assert observations > 0
    assert not missing


def test_late_output_swap_after_cleanup_retains_no_owned_private_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    displaced = tmp_path / "displaced"
    swapped = False

    def swap_after_cleanup(name: str) -> None:
        nonlocal swapped
        if name != "cleanup-complete" or swapped:
            return
        output.rename(displaced)
        output.mkdir(mode=0o700)
        (output / "attacker").write_bytes(b"attacker\n")
        (output / "attacker").chmod(0o600)
        swapped = True

    monkeypatch.setattr(
        contract_generator_common,
        "_transaction_checkpoint",
        swap_after_cleanup,
    )
    assert _run_directory_generator(output, ["--write"], _alternate_directory_render) == 1
    assert swapped
    assert not _transaction_path(output).exists()
    assert (output / "attacker").read_bytes() == b"attacker\n"
    assert {path.name: path.read_bytes() for path in displaced.iterdir()} == (
        _alternate_directory_render()
    )


def test_initial_publication_uses_noreplace_and_retains_ambiguous_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "v1"
    real_noreplace = contract_generator_common._atomic_noreplace
    injected = False

    def race_noreplace(
        source_parent_fd: int,
        source_name: str,
        destination_parent_fd: int,
        destination_name: str,
    ) -> None:
        nonlocal injected
        if destination_name == output.name and not injected:
            output.mkdir(mode=0o700)
            (output / "attacker").write_bytes(b"attacker\n")
            (output / "attacker").chmod(0o600)
            injected = True
        real_noreplace(
            source_parent_fd,
            source_name,
            destination_parent_fd,
            destination_name,
        )

    monkeypatch.setattr(contract_generator_common, "_atomic_noreplace", race_noreplace)
    assert _run_directory_generator(output, ["--write"]) == 1
    assert injected
    assert (output / "attacker").read_bytes() == b"attacker\n"
    assert _transaction_path(output).is_dir()


def test_unsupported_platform_fails_before_path_touch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "missing" / "v1"
    before = _tree_snapshot(tmp_path)
    monkeypatch.setattr(sys, "platform", "win32")
    assert _run_directory_generator(output, ["--write"]) == 1
    assert _tree_snapshot(tmp_path) == before


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin native gate")
def test_darwin_native_swap_exclusive_and_parent_flock_gate(tmp_path: Path) -> None:
    assert contract_generator_common._native_function("renameatx_np")
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    assert _run_directory_generator(output, ["--write"], _alternate_directory_render) == 0


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux native gate")
def test_linux_native_exchange_noreplace_and_parent_flock_gate(tmp_path: Path) -> None:
    assert contract_generator_common._native_function("renameat2")
    output = tmp_path / "v1"
    assert _run_directory_generator(output, ["--write"]) == 0
    assert _run_directory_generator(output, ["--write"], _alternate_directory_render) == 0
