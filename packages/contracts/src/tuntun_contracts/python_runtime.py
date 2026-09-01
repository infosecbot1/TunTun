from __future__ import annotations

import re
from typing import Annotated

from pydantic import AfterValidator, Field

CANONICAL_PYTHON_VERSION_PATTERN = (
    r"^(?:0|[1-9][0-9]{0,2})[.]"
    r"(?:0|[1-9][0-9]{0,2})[.]"
    r"(?:0|[1-9][0-9]{0,2})$"
)
_CANONICAL_PYTHON_VERSION = re.compile(CANONICAL_PYTHON_VERSION_PATTERN)


def parse_canonical_python_version(value: str) -> tuple[int, int, int]:
    """Parse exactly one stable, canonical three-component Python version."""

    if type(value) is not str or _CANONICAL_PYTHON_VERSION.fullmatch(value) is None:
        raise ValueError("Python version must be a canonical stable three-component version")
    major, minor, patch = value.split(".")
    return int(major), int(minor), int(patch)


def _require_canonical_python_version(value: str) -> str:
    parse_canonical_python_version(value)
    return value


CanonicalPythonVersion = Annotated[
    str,
    Field(
        min_length=5,
        max_length=11,
        pattern=CANONICAL_PYTHON_VERSION_PATTERN,
        json_schema_extra={"not": {"pattern": r"[\r\n]"}},
    ),
    AfterValidator(_require_canonical_python_version),
]
