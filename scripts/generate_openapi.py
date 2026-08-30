from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import yaml  # type: ignore[import-untyped]  # PyYAML 6 has no py.typed marker.
from tuntun_contracts.base import registered_contract_models

if TYPE_CHECKING:
    from scripts.contract_generator_common import build_model_schemas, run_generator
elif __package__:
    from .contract_generator_common import build_model_schemas, run_generator
else:
    from contract_generator_common import build_model_schemas, run_generator

OUTPUT_PATH: Final = Path("packages/contracts/openapi/admin-v1.yaml")


def render() -> bytes:
    document: dict[str, object] = {
        "openapi": "3.1.0",
        "info": {
            "title": "Tuntun Admin API",
            "version": "1.0.0",
            "description": "Foundation contract components; no HTTP paths are owned yet.",
        },
        "paths": {},
        "components": {
            "schemas": build_model_schemas(
                registered_contract_models(),
                container_pointer="/components/schemas",
            )
        },
    }
    rendered = cast(
        str,
        yaml.safe_dump(
            document,
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
            width=100,
        ),
    )
    return rendered.encode("utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    return run_generator(
        output_path=OUTPUT_PATH,
        renderer=render,
        argv=argv,
    )


if __name__ == "__main__":
    raise SystemExit(main())
