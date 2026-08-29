from __future__ import annotations

import argparse
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from assurance_common import (
        MAX_JSON_CONTAINERS,
        MAX_JSON_DEPTH,
        MAX_JSON_TOKENS,
        MAX_REGULAR_FILE_BYTES,
        MAX_WALK_FILES,
        MAX_WALK_TOTAL_BYTES,
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        CsvSet,
        finish,
        incomplete,
        lexical_path,
        parse_json_object,
        read_json_object,
        read_regular_file,
        walk_regular_files,
    )
elif __package__:
    from .assurance_common import (
        MAX_JSON_CONTAINERS,
        MAX_JSON_DEPTH,
        MAX_JSON_TOKENS,
        MAX_REGULAR_FILE_BYTES,
        MAX_WALK_FILES,
        MAX_WALK_TOTAL_BYTES,
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        CsvSet,
        finish,
        incomplete,
        lexical_path,
        parse_json_object,
        read_json_object,
        read_regular_file,
        walk_regular_files,
    )
else:
    from assurance_common import (
        MAX_JSON_CONTAINERS,
        MAX_JSON_DEPTH,
        MAX_JSON_TOKENS,
        MAX_REGULAR_FILE_BYTES,
        MAX_WALK_FILES,
        MAX_WALK_TOTAL_BYTES,
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        CsvSet,
        finish,
        incomplete,
        lexical_path,
        parse_json_object,
        read_json_object,
        read_regular_file,
        walk_regular_files,
    )

TOOL = "feature-absence"
FEATURE_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,127}")


def _parser() -> ClosedArgumentParser:
    parser = ClosedArgumentParser(prog="check_feature_absence.py")
    parser.add_argument("--root", default=".")
    parser.add_argument("--manifest")
    parser.add_argument("--feature")
    parser.add_argument("--features", type=CsvSet.parse)
    parser.add_argument("--phase", type=int)
    parser.add_argument("--all-canonically-absent", action="store_true")
    parser.add_argument("--direct-and-replay", action="store_true")
    return parser


def _manifest_path(root: Path, value: str | None) -> Path:
    if value is None:
        return root / ".assurance" / "features.json"
    candidate = Path(value)
    return lexical_path(candidate if candidate.is_absolute() else root / candidate)


def _selectors(arguments: argparse.Namespace) -> tuple[str, ...] | None:
    manifest = arguments.manifest
    feature = arguments.feature
    features = arguments.features
    phase = arguments.phase
    all_absent = arguments.all_canonically_absent
    direct = arguments.direct_and_replay
    valid = False
    selected: tuple[str, ...] | None = None
    if (
        manifest is not None
        and (feature is not None) != (features is not None)
        and phase is None
        or manifest is None
        and (feature is not None) != (features is not None)
        and phase is not None
    ):
        valid = not all_absent
        selected = (feature,) if feature is not None else tuple(features)
    elif (
        all_absent
        and direct
        and manifest is None
        and feature is None
        and features is None
        and phase is None
    ):
        valid = True
    if not valid:
        raise ValueError("exactly one closed selector mode is required")
    return selected


def _json(path: Path, raw: bytes) -> Mapping[str, object]:
    try:
        return parse_json_object(
            raw,
            max_depth=MAX_JSON_DEPTH,
            max_containers=MAX_JSON_CONTAINERS,
            max_tokens=MAX_JSON_TOKENS,
        )
    except ValueError as error:
        raise AssuranceInputError(path, str(error)) from error


def evaluate(argv: Sequence[str] | None = None) -> AssuranceResult:
    try:
        arguments = _parser().parse_args(argv)
        selected = _selectors(arguments)
        if arguments.phase is not None and not 1 <= arguments.phase <= 99:
            raise ValueError("phase must be canonical")
        if selected is not None and (
            not selected
            or len(set(selected)) != len(selected)
            or any(FEATURE_ID.fullmatch(item) is None for item in selected)
        ):
            raise ValueError("feature IDs must be unique and canonical")
        root = lexical_path(arguments.root)
        manifest_path = _manifest_path(root, arguments.manifest)
        frozen = tuple(
            walk_regular_files(
                (root,), max_files=MAX_WALK_FILES, max_total_bytes=MAX_WALK_TOTAL_BYTES
            )
        )
        files = {item.path: item.raw for item in frozen}
        manifest = read_json_object(manifest_path, max_bytes=MAX_REGULAR_FILE_BYTES)
        features = manifest.get("features")
        surfaces = manifest.get("surfaces")
        if not isinstance(features, Mapping) or not isinstance(surfaces, list):
            raise AssuranceInputError(manifest_path, "feature-manifest-invalid")
        if not all(isinstance(path, str) for path in surfaces):
            raise AssuranceInputError(manifest_path, "surface-inventory-invalid")
        if selected is None:
            selected = tuple(
                key
                for key, value in features.items()
                if isinstance(key, str)
                and isinstance(value, Mapping)
                and value.get("state") == "absent"
            )
            if not selected:
                raise AssuranceInputError(manifest_path, "canonical-absence-inventory-empty")
        for feature in selected:
            declaration = features.get(feature)
            if not isinstance(declaration, Mapping):
                raise AssuranceInputError(manifest_path, "unknown-feature", feature)
            if declaration.get("state") != "absent":
                raise AssuranceInputError(manifest_path, "feature-not-declared-absent", feature)
            if arguments.phase is not None and declaration.get("phase") != arguments.phase:
                raise AssuranceInputError(manifest_path, "feature-phase-mismatch", feature)
    except AssuranceInputError as error:
        return incomplete(TOOL, error)
    except (ValueError, TypeError) as error:
        return AssuranceResult(
            TOOL, False, (AssuranceFinding(Path("."), "invalid-arguments", str(error)),)
        )

    findings: list[AssuranceFinding] = []
    for relative_value in surfaces:
        assert isinstance(relative_value, str)
        relative = Path(relative_value)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            return AssuranceResult(
                TOOL,
                False,
                (AssuranceFinding(manifest_path, "surface-path-invalid", relative_value),),
            )
        path = root / relative
        raw = files.get(path)
        if raw is None:
            try:
                raw = read_regular_file(path, max_bytes=MAX_REGULAR_FILE_BYTES)
            except AssuranceInputError as error:
                return incomplete(TOOL, error)
        if path.suffix == ".json":
            try:
                _json(path, raw)
            except AssuranceInputError as error:
                return incomplete(TOOL, error)
        lowered = raw.lower()
        for feature in selected:
            if feature.encode("utf-8").lower() in lowered:
                findings.append(AssuranceFinding(path, "feature-registered", feature))
    if arguments.direct_and_replay:
        direct_path = root / ".assurance" / "direct_replay.json"
        raw = files.get(direct_path)
        if raw is None:
            try:
                raw = read_regular_file(direct_path, max_bytes=MAX_REGULAR_FILE_BYTES)
            except AssuranceInputError as error:
                return incomplete(TOOL, error)
        try:
            probes = _json(direct_path, raw)
        except AssuranceInputError as error:
            return incomplete(TOOL, error)
        expected = {"direct_request": "schema-unsupported", "replay": "no-route"}
        for name, result in expected.items():
            record = probes.get(name)
            if not isinstance(record, Mapping):
                return AssuranceResult(
                    TOOL,
                    False,
                    (AssuranceFinding(direct_path, "probe-inventory-invalid", name),),
                )
            if record.get("result") != result or record.get("side_effects") is not False:
                findings.append(AssuranceFinding(direct_path, "feature-reachable", name))
    return AssuranceResult(TOOL, True, tuple(findings))


def main(argv: Sequence[str] | None = None) -> int:
    return finish(evaluate(argv))


if __name__ == "__main__":
    raise SystemExit(main())
