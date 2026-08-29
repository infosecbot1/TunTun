from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Final

from tuntun_contracts.base import registered_contract_models

if TYPE_CHECKING:
    from scripts.contract_generator_common import (
        build_model_schemas,
        render_json_document,
        run_generator,
    )
elif __package__:
    from .contract_generator_common import (
        build_model_schemas,
        render_json_document,
        run_generator,
    )
else:
    from contract_generator_common import (
        build_model_schemas,
        render_json_document,
        run_generator,
    )

OUTPUT_PATH: Final = Path("packages/contracts/schema/v1/contracts.schema.json")


def render() -> bytes:
    document: dict[str, object] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "schema_version": "1.0",
        "models": build_model_schemas(
            registered_contract_models(),
            container_pointer="/models",
        ),
    }
    return render_json_document(document)


def main(argv: Sequence[str] | None = None) -> int:
    return run_generator(
        output_path=OUTPUT_PATH,
        renderer=render,
        argv=argv,
    )


if __name__ == "__main__":
    raise SystemExit(main())
