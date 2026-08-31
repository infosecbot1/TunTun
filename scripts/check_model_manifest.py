from __future__ import annotations

import argparse
import json
from pathlib import Path

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from tuntun_core.services.models.fs import read_bounded_strict_yaml
from tuntun_core.services.models.registry import ModelRegistry

_REPOSITORY_ROOT = Path(__file__).parents[1]
_SCHEMA = _REPOSITORY_ROOT / "models" / "manifest.schema.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a governed Tuntun model manifest")
    parser.add_argument("manifest", type=Path)
    arguments = parser.parse_args()
    document = read_bounded_strict_yaml(arguments.manifest)
    schema = json.loads(_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)
    ModelRegistry.from_document(document)
    print("model manifest: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
