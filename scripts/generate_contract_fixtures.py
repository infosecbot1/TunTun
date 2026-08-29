from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Final

from tuntun_contracts.base import canonical_bytes

if TYPE_CHECKING:
    from scripts.contract_fixture_builders import (
        BUILDERS,
        FixtureFactory,
        fixture_registry,
        validate_builder_partition,
    )
    from scripts.contract_generator_common import run_directory_generator
elif __package__:
    from .contract_fixture_builders import (
        BUILDERS,
        FixtureFactory,
        fixture_registry,
        validate_builder_partition,
    )
    from .contract_generator_common import run_directory_generator
else:
    from contract_fixture_builders import (
        BUILDERS,
        FixtureFactory,
        fixture_registry,
        validate_builder_partition,
    )
    from contract_generator_common import run_directory_generator

OUTPUT_DIRECTORY: Final = Path("packages/contracts/fixtures/v1")
FIXTURE_FILENAMES: Final = (
    "actions.json",
    "audit.json",
    "budget.json",
    "events.json",
    "identity.json",
    "memory.json",
    "policy.json",
    "provider.json",
    "reachy.json",
    "speech.json",
)


def _render_document(document: Mapping[str, object]) -> bytes:
    return (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def render() -> dict[str, bytes]:
    validate_builder_partition()
    registry = fixture_registry()
    if tuple(f"{group}.json" for group in registry) != FIXTURE_FILENAMES:
        raise RuntimeError("fixture group inventory differs from output filenames")
    public_models = {model_type for models in registry.values() for model_type in models.values()}
    if set(BUILDERS) != public_models:
        raise RuntimeError("fixture builder inventory is incomplete")

    factory = FixtureFactory(first_uuid=101)
    rendered: dict[str, bytes] = {}
    for group, models in registry.items():
        examples: dict[str, object] = {}
        canonical_examples: dict[str, str] = {}
        for name, model_type in models.items():
            model = factory.build(model_type)
            examples[name] = model.model_dump(mode="json")
            canonical_examples[name] = canonical_bytes(model).decode("utf-8")
        rendered[f"{group}.json"] = _render_document(
            {
                "canonical_examples": canonical_examples,
                "examples": examples,
                "schema_version": "1.0",
            }
        )
    return rendered


def main(argv: Sequence[str] | None = None) -> int:
    return run_directory_generator(
        output_directory=OUTPUT_DIRECTORY,
        expected_names=FIXTURE_FILENAMES,
        renderer=render,
        argv=argv,
    )


if __name__ == "__main__":
    raise SystemExit(main())
