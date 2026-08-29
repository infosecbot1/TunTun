from __future__ import annotations

import argparse
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts.assurance_common import (
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
        read_frozen_regular_file,
        revalidate_frozen_inventory,
        revalidate_frozen_regular_file,
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
        read_frozen_regular_file,
        revalidate_frozen_inventory,
        revalidate_frozen_regular_file,
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
        read_frozen_regular_file,
        revalidate_frozen_inventory,
        revalidate_frozen_regular_file,
        walk_regular_files,
    )

TOOL = "feature-absence"
FEATURE_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,127}")
REQUIRED_SURFACES = (
    "src/feature_registry.py",
    "config/features.json",
    "api/routes.json",
    "openapi/openapi.json",
    "package.json",
    "apps/admin/dist/assets/app.js",
    "ipc/services.json",
    "launchd/services.json",
)


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
    one_feature_selector = (feature is not None) != (features is not None)
    manifest_mode = manifest is not None and one_feature_selector and phase is None
    phase_mode = manifest is None and one_feature_selector and phase is not None
    if (manifest_mode or phase_mode) and not all_absent and not direct:
        valid = True
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
        captured = {item.path: item for item in frozen}
        supplemental = []
        total_bytes = sum(item.size for item in frozen)
        required_paths = (
            manifest_path,
            *(root / relative for relative in REQUIRED_SURFACES),
            root / ".assurance" / "direct_replay.json",
        )
        for path in required_paths:
            if path in captured:
                continue
            if len(captured) >= MAX_WALK_FILES:
                raise AssuranceInputError(path, "file-count-limit")
            item = read_frozen_regular_file(path, max_bytes=MAX_REGULAR_FILE_BYTES)
            total_bytes += item.size
            if total_bytes > MAX_WALK_TOTAL_BYTES:
                raise AssuranceInputError(path, "total-byte-limit")
            captured[path] = item
            supplemental.append(item)
        files = {path: item.raw for path, item in captured.items()}
        manifest = _json(manifest_path, files[manifest_path])
        features = manifest.get("features")
        surfaces = manifest.get("surfaces")
        if not isinstance(features, Mapping) or not isinstance(surfaces, list):
            raise AssuranceInputError(manifest_path, "feature-manifest-invalid")
        if tuple(surfaces) != REQUIRED_SURFACES:
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
        raw = files[path]
        if path.suffix == ".json":
            try:
                _json(path, raw)
            except AssuranceInputError as error:
                return incomplete(TOOL, error)
        lowered = raw.lower()
        for feature in selected:
            if feature.encode("utf-8").lower() in lowered:
                findings.append(AssuranceFinding(path, "feature-registered", feature))
    direct_path = root / ".assurance" / "direct_replay.json"
    raw = files[direct_path]
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
    try:
        revalidate_frozen_inventory(
            (root,),
            frozen,
            max_files=MAX_WALK_FILES,
            max_total_bytes=MAX_WALK_TOTAL_BYTES,
        )
        for item in supplemental:
            revalidate_frozen_regular_file(item)
    except AssuranceInputError as error:
        return incomplete(TOOL, error)
    return AssuranceResult(TOOL, True, tuple(findings))


def main(argv: Sequence[str] | None = None) -> int:
    return finish(evaluate(argv))


if __name__ == "__main__":
    raise SystemExit(main())
