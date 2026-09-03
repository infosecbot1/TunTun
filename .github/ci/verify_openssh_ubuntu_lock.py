#!/usr/bin/env python3
"""Verify and materialize the Ubuntu 24.04 OpenSSH package closure lock."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import lzma
import os
import re
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, cast

LOCK_SCHEMA_VERSION = "tuntun.openssh-ubuntu-24.04.lock.v1"
RUNNER = "ubuntu-24.04"
ROOT_PACKAGES = ("openssh-client", "openssh-server", "openssh-sftp-server")
DEPENDENCY_FIELDS = ("Pre-Depends", "Depends")
ARCHITECTURES = ("amd64", "all")
COMPONENT = "main"
PACKAGE_INDEX_RELATIVE_PATH = "main/binary-amd64/Packages.xz"
DEFAULT_LOCK_PATH = Path(".github/ci/openssh-ubuntu-24.04.lock")
DEFAULT_KEYRING = Path("/usr/share/keyrings/ubuntu-archive-keyring.gpg")
BOOTSTRAP_KEYRING_URL = (
    "https://archive.ubuntu.com/ubuntu/pool/main/u/ubuntu-keyring/"
    "ubuntu-keyring_2023.11.28.1_all.deb"
)
BOOTSTRAP_KEYRING_TAR_PATH = PurePosixPath("usr/share/keyrings/ubuntu-archive-keyring.gpg")
BOOTSTRAP_KEYRING_MAX_TAR_MEMBERS = 256
BOOTSTRAP_KEYRING_MAX_FILE_BYTES = 4 * 1024 * 1024
BOOTSTRAP_KEYRING_MAX_TOTAL_BYTES = 64 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024
SOURCE_ORDER: tuple[dict[str, str], ...] = (
    {
        "id": "archive-noble-main-amd64",
        "origin": "Ubuntu",
        "suite": "noble",
        "component": COMPONENT,
        "architecture": "amd64",
        "base_url": "https://archive.ubuntu.com/ubuntu/",
    },
    {
        "id": "archive-noble-updates-main-amd64",
        "origin": "Ubuntu",
        "suite": "noble-updates",
        "component": COMPONENT,
        "architecture": "amd64",
        "base_url": "https://archive.ubuntu.com/ubuntu/",
    },
    {
        "id": "security-noble-security-main-amd64",
        "origin": "Ubuntu",
        "suite": "noble-security",
        "component": COMPONENT,
        "architecture": "amd64",
        "base_url": "https://security.ubuntu.com/ubuntu/",
    },
)
SOURCE_PRIORITY = {
    "archive-noble-main-amd64": 0,
    "archive-noble-updates-main-amd64": 1,
    "security-noble-security-main-amd64": 2,
}
FIELD_NAME_RE = re.compile(rb"^[A-Za-z0-9][A-Za-z0-9-]*: ")
RELATION_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9+.-]*)(?::[A-Za-z0-9-]+)?"
    r"(?:\s*\((<<|<=|=|>=|>>)\s*([^)]+)\))?"
)


@dataclass(frozen=True, slots=True)
class PackageRecord:
    index_id: str
    base_url: str
    fields: Mapping[str, str]
    record_sha256: str

    @property
    def name(self) -> str:
        return self.fields["Package"]

    @property
    def version(self) -> str:
        return self.fields["Version"]

    @property
    def architecture(self) -> str:
        return self.fields["Architecture"]

    @property
    def filename(self) -> str:
        return self.fields["Filename"]

    @property
    def size(self) -> int:
        return int(self.fields["Size"])

    @property
    def sha256(self) -> str:
        return self.fields["SHA256"]

    @property
    def url(self) -> str:
        return f"{self.base_url}{self.filename}"


@dataclass(frozen=True, slots=True)
class DependencyAlternative:
    name: str
    operator: str | None
    version: str | None


def fetch_url(url: str, *, max_bytes: int | None = None) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:
        if max_bytes is None:
            return cast(bytes, response.read())
        return cast(bytes, response.read(max_bytes + 1))


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    decoded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(decoded, dict):
        raise SystemExit("lock must be a JSON object")
    return decoded


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=False, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def verify_gpgv(*, keyring: Path, inrelease_path: Path) -> None:
    subprocess.run(
        [
            "gpgv",
            "--keyring",
            str(keyring),
            str(inrelease_path),
        ],
        check=True,
        capture_output=True,
    )


def parse_inrelease_sha256(raw: bytes) -> dict[str, tuple[str, int]]:
    entries: dict[str, tuple[str, int]] = {}
    in_sha256 = False
    for line in raw.decode("utf-8", "replace").splitlines():
        if line == "SHA256:":
            in_sha256 = True
            continue
        if not in_sha256:
            continue
        if not line.startswith(" "):
            break
        parts = line.split()
        if len(parts) != 3:
            continue
        digest, size, relative_path = parts
        entries[relative_path] = (digest, int(size))
    return entries


def parse_control_stanza(stanza: bytes) -> dict[str, str]:
    fields: dict[str, str] = {}
    current: str | None = None
    for line in stanza.splitlines():
        if line.startswith(b" "):
            if current is not None:
                fields[current] = f"{fields[current]}\n{line[1:].decode('utf-8', 'replace')}"
            continue
        if FIELD_NAME_RE.match(line) is None:
            continue
        name_raw, value_raw = line.split(b": ", 1)
        current = name_raw.decode("ascii")
        fields[current] = value_raw.decode("utf-8", "replace")
    return fields


def parse_packages(raw_xz: bytes, *, index_id: str, base_url: str) -> dict[str, PackageRecord]:
    raw = lzma.decompress(raw_xz)
    records: dict[str, PackageRecord] = {}
    for stanza in raw.split(b"\n\n"):
        if not stanza.strip():
            continue
        fields = parse_control_stanza(stanza)
        if fields.get("Architecture") not in ARCHITECTURES:
            continue
        for required in ("Package", "Version", "Architecture", "Filename", "Size", "SHA256"):
            if required not in fields:
                raise SystemExit(f"package record missing {required}: {fields.get('Package')}")
        key = (
            f"{fields['Package']}={fields['Version']}@{fields['Architecture']}:{fields['Filename']}"
        )
        records[key] = PackageRecord(
            index_id=index_id,
            base_url=base_url,
            fields=fields,
            record_sha256=sha256_bytes(stanza),
        )
    return records


def source_inrelease_url(source: Mapping[str, str]) -> str:
    return f"{source['base_url']}dists/{source['suite']}/InRelease"


def source_packages_url(source: Mapping[str, str]) -> str:
    return f"{source['base_url']}dists/{source['suite']}/{PACKAGE_INDEX_RELATIVE_PATH}"


def fetch_verified_metadata(
    *,
    lock: Mapping[str, Any] | None,
    keyring: Path,
    work_root: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, dict[str, PackageRecord]]]:
    if lock is None:
        sources = [dict(source) for source in SOURCE_ORDER]
    else:
        signed_origins = lock.get("signed_origins")
        if not isinstance(signed_origins, list):
            raise SystemExit("lock signed_origins must be a list")
        sources = []
        for origin in signed_origins:
            if not isinstance(origin, dict):
                raise SystemExit("signed origin must be an object")
            sources.append(
                {
                    "id": str(origin["id"]),
                    "origin": str(origin["origin"]),
                    "suite": str(origin["suite"]),
                    "component": str(origin["component"]),
                    "architecture": str(origin["architecture"]),
                    "base_url": str(origin["base_url"]),
                }
            )

    expected_indexes_by_id = {}
    if lock is not None:
        package_indexes = lock.get("package_indexes")
        if not isinstance(package_indexes, list):
            raise SystemExit("lock package_indexes must be a list")
        expected_indexes_by_id = {str(index["id"]): index for index in package_indexes}

    origins: list[dict[str, Any]] = []
    indexes: list[dict[str, Any]] = []
    records_by_index: dict[str, dict[str, PackageRecord]] = {}
    for source in sources:
        origin_id = source["id"]
        inrelease_url = source_inrelease_url(source)
        inrelease_raw = fetch_url(inrelease_url)
        inrelease_path = work_root / f"{origin_id}.InRelease"
        inrelease_path.write_bytes(inrelease_raw)
        verify_gpgv(keyring=keyring, inrelease_path=inrelease_path)
        origin = {
            **source,
            "inrelease_url": inrelease_url,
            "inrelease_size_bytes": len(inrelease_raw),
            "inrelease_sha256": sha256_bytes(inrelease_raw),
        }
        if lock is not None:
            locked_origin = next(item for item in lock["signed_origins"] if item["id"] == origin_id)
            if origin != locked_origin:
                raise SystemExit(f"signed origin drift: {origin_id}")
        origins.append(origin)

        inrelease_sha256 = parse_inrelease_sha256(inrelease_raw)
        expected_index_sha, expected_index_size = inrelease_sha256[PACKAGE_INDEX_RELATIVE_PATH]
        packages_url = source_packages_url(source)
        packages_raw = fetch_url(packages_url, max_bytes=expected_index_size)
        observed_index_id = f"{origin_id}-packages-xz"
        observed_index = {
            "id": observed_index_id,
            "origin_id": origin_id,
            "suite": source["suite"],
            "component": source["component"],
            "architecture": source["architecture"],
            "relative_path": PACKAGE_INDEX_RELATIVE_PATH,
            "url": packages_url,
            "size_bytes": len(packages_raw),
            "sha256": sha256_bytes(packages_raw),
            "compression": "xz",
        }
        if observed_index["size_bytes"] != expected_index_size:
            raise SystemExit(f"package index size mismatch: {packages_url}")
        if observed_index["sha256"] != expected_index_sha:
            raise SystemExit(f"package index digest mismatch: {packages_url}")
        if lock is not None and observed_index != expected_indexes_by_id[observed_index_id]:
            raise SystemExit(f"package index lock drift: {observed_index_id}")
        indexes.append(observed_index)
        records_by_index[observed_index_id] = parse_packages(
            packages_raw,
            index_id=observed_index_id,
            base_url=source["base_url"],
        )
    return origins, indexes, records_by_index


def split_relation_groups(value: str | None) -> list[str]:
    if value is None or value == "":
        return []
    groups: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(value):
        if char in "([":
            depth += 1
        elif char in ")]" and depth > 0:
            depth -= 1
        elif char == "," and depth == 0:
            groups.append(value[start:index].strip())
            start = index + 1
    groups.append(value[start:].strip())
    return [group for group in groups if group]


def parse_dependency_alternative(value: str) -> DependencyAlternative | None:
    value = value.split("[", 1)[0].split("<", 1)[0].strip()
    match = RELATION_RE.match(value)
    if match is None:
        return None
    name, operator, version = match.groups()
    return DependencyAlternative(name=name, operator=operator, version=version)


def split_version(value: str) -> tuple[int, str, str]:
    if ":" in value:
        epoch_raw, rest = value.split(":", 1)
        epoch = int(epoch_raw)
    else:
        epoch = 0
        rest = value
    if "-" in rest:
        upstream, revision = rest.rsplit("-", 1)
    else:
        upstream = rest
        revision = ""
    return epoch, upstream, revision


def debian_char_order(char: str | None) -> int:
    if char is None:
        return 0
    if char == "~":
        return -1
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def compare_version_part(left: str, right: str) -> int:
    left_index = 0
    right_index = 0
    while left_index < len(left) or right_index < len(right):
        while (
            left_index < len(left)
            and not left[left_index].isdigit()
            or right_index < len(right)
            and not right[right_index].isdigit()
        ):
            left_char = left[left_index] if left_index < len(left) else None
            right_char = right[right_index] if right_index < len(right) else None
            left_order = debian_char_order(left_char)
            right_order = debian_char_order(right_char)
            if left_order != right_order:
                return -1 if left_order < right_order else 1
            if left_char is not None:
                left_index += 1
            if right_char is not None:
                right_index += 1
        while left_index < len(left) and left[left_index] == "0":
            left_index += 1
        while right_index < len(right) and right[right_index] == "0":
            right_index += 1
        left_digit_start = left_index
        right_digit_start = right_index
        while left_index < len(left) and left[left_index].isdigit():
            left_index += 1
        while right_index < len(right) and right[right_index].isdigit():
            right_index += 1
        left_digits = left[left_digit_start:left_index]
        right_digits = right[right_digit_start:right_index]
        if len(left_digits) != len(right_digits):
            return -1 if len(left_digits) < len(right_digits) else 1
        if left_digits != right_digits:
            return -1 if left_digits < right_digits else 1
    return 0


def compare_debian_versions(left: str, right: str) -> int:
    left_epoch, left_upstream, left_revision = split_version(left)
    right_epoch, right_upstream, right_revision = split_version(right)
    if left_epoch != right_epoch:
        return -1 if left_epoch < right_epoch else 1
    upstream_result = compare_version_part(left_upstream, right_upstream)
    if upstream_result != 0:
        return upstream_result
    return compare_version_part(left_revision, right_revision)


def version_satisfies(version: str, alternative: DependencyAlternative) -> bool:
    if alternative.operator is None:
        return True
    if alternative.version is None:
        return False
    comparison = compare_debian_versions(version, alternative.version)
    if alternative.operator == "<<":
        return comparison < 0
    if alternative.operator == "<=":
        return comparison <= 0
    if alternative.operator == "=":
        return comparison == 0
    if alternative.operator == ">=":
        return comparison >= 0
    if alternative.operator == ">>":
        return comparison > 0
    return False


def record_satisfies(
    record: PackageRecord | Mapping[str, Any],
    alternative: DependencyAlternative,
) -> bool:
    version = record.version if isinstance(record, PackageRecord) else str(record["version"])
    return version_satisfies(version, alternative)


def candidate_sort_key(record: PackageRecord) -> tuple[str, int, int]:
    return (
        record.version,
        SOURCE_PRIORITY.get(record.index_id.removesuffix("-packages-xz"), -1),
        1 if record.architecture == "amd64" else 0,
    )


def better_candidate(left: PackageRecord, right: PackageRecord) -> PackageRecord:
    version_comparison = compare_debian_versions(left.version, right.version)
    if version_comparison != 0:
        return left if version_comparison > 0 else right
    left_source = SOURCE_PRIORITY.get(left.index_id.removesuffix("-packages-xz"), -1)
    right_source = SOURCE_PRIORITY.get(right.index_id.removesuffix("-packages-xz"), -1)
    if left_source != right_source:
        return left if left_source > right_source else right
    if left.architecture != right.architecture:
        return left if left.architecture == "amd64" else right
    return left if left.filename <= right.filename else right


def build_candidate_maps(
    records_by_index: Mapping[str, Mapping[str, PackageRecord]],
) -> tuple[dict[str, list[PackageRecord]], dict[str, list[PackageRecord]]]:
    by_name: dict[str, list[PackageRecord]] = {}
    providers: dict[str, list[PackageRecord]] = {}
    for records in records_by_index.values():
        for record in records.values():
            by_name.setdefault(record.name, []).append(record)
            for provided in split_relation_groups(record.fields.get("Provides")):
                alternative = parse_dependency_alternative(provided)
                if alternative is not None:
                    providers.setdefault(alternative.name, []).append(record)
    return by_name, providers


def select_best_candidate(
    candidates: Sequence[PackageRecord],
    alternative: DependencyAlternative,
) -> PackageRecord | None:
    best: PackageRecord | None = None
    for candidate in candidates:
        if not record_satisfies(candidate, alternative):
            continue
        best = candidate if best is None else better_candidate(best, candidate)
    return best


def choose_dependency_record(
    relation_group: str,
    by_name: Mapping[str, Sequence[PackageRecord]],
    providers: Mapping[str, Sequence[PackageRecord]],
) -> PackageRecord | None:
    for raw_alternative in relation_group.split("|"):
        alternative = parse_dependency_alternative(raw_alternative)
        if alternative is None:
            continue
        candidate = select_best_candidate(by_name.get(alternative.name, ()), alternative)
        if candidate is not None:
            return candidate
        provider = select_best_candidate(providers.get(alternative.name, ()), alternative)
        if provider is not None:
            return provider
    return None


def resolve_complete_closure(
    records_by_index: Mapping[str, Mapping[str, PackageRecord]],
) -> list[PackageRecord]:
    by_name, providers = build_candidate_maps(records_by_index)
    selected: dict[str, PackageRecord] = {}
    pending = list(ROOT_PACKAGES)
    while pending:
        package_name = pending.pop(0)
        alternative = DependencyAlternative(name=package_name, operator=None, version=None)
        record = select_best_candidate(by_name.get(package_name, ()), alternative)
        if record is None:
            raise SystemExit(f"missing package candidate: {package_name}")
        previous = selected.get(record.name)
        if previous is not None:
            replacement = better_candidate(previous, record)
            if replacement is previous:
                continue
            selected[record.name] = replacement
        else:
            selected[record.name] = record
        for field in DEPENDENCY_FIELDS:
            for relation_group in split_relation_groups(record.fields.get(field)):
                dependency = choose_dependency_record(relation_group, by_name, providers)
                if dependency is None:
                    raise SystemExit(f"unresolved dependency for {record.name}: {relation_group}")
                if dependency.name not in selected and dependency.name not in pending:
                    pending.append(dependency.name)
    return [selected[name] for name in sorted(selected)]


def package_to_lock_record(record: PackageRecord) -> dict[str, Any]:
    return {
        "name": record.name,
        "version": record.version,
        "architecture": record.architecture,
        "source_index_id": record.index_id,
        "filename": record.filename,
        "url": record.url,
        "size_bytes": record.size,
        "sha256": record.sha256,
        "record_sha256": record.record_sha256,
        "pre_depends": split_relation_groups(record.fields.get("Pre-Depends")),
        "depends": split_relation_groups(record.fields.get("Depends")),
        "provides": split_relation_groups(record.fields.get("Provides")),
    }


def derive_lock(*, keyring: Path, work_root: Path) -> dict[str, Any]:
    origins, indexes, records_by_index = fetch_verified_metadata(
        lock=None,
        keyring=keyring,
        work_root=work_root,
    )
    package_records = resolve_complete_closure(records_by_index)
    lock = {
        "schema_version": LOCK_SCHEMA_VERSION,
        "runner": RUNNER,
        "closure_scope": {
            "locked_package_set": (
                "Complete transitive Depends/Pre-Depends closure for openssh-client, "
                "openssh-server, and openssh-sftp-server on Ubuntu 24.04 amd64 from signed "
                "main archive pockets."
            ),
            "closure_status": "complete_signed_packages_closure",
            "root_packages": list(ROOT_PACKAGES),
            "dependency_fields": list(DEPENDENCY_FIELDS),
            "components": [COMPONENT],
            "architectures": list(ARCHITECTURES),
            "suites": [source["suite"] for source in SOURCE_ORDER],
        },
        "signed_origins": origins,
        "package_indexes": indexes,
        "packages": [package_to_lock_record(record) for record in package_records],
    }
    verify_complete_dependency_closure(lock)
    return lock


def packages_by_name(lock: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    packages = lock.get("packages")
    if not isinstance(packages, list):
        raise SystemExit("lock packages must be a list")
    by_name: dict[str, Mapping[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise SystemExit("locked package must be an object")
        name = str(package["name"])
        if name in by_name:
            raise SystemExit(f"duplicate locked package: {name}")
        by_name[name] = package
    return by_name


def verify_complete_dependency_closure(lock: Mapping[str, Any]) -> None:
    if lock.get("schema_version") != LOCK_SCHEMA_VERSION:
        raise SystemExit("unexpected lock schema version")
    if lock.get("runner") != RUNNER:
        raise SystemExit("unexpected lock runner")
    closure = lock.get("closure_scope")
    if not isinstance(closure, dict):
        raise SystemExit("lock closure_scope must be an object")
    if closure.get("closure_status") != "complete_signed_packages_closure":
        raise SystemExit("OpenSSH package closure is not complete")
    if "base_dependency_policy" in closure or "blocker" in closure:
        raise SystemExit("OpenSSH lock must not rely on runner base policy or blocker stubs")

    by_name = packages_by_name(lock)
    provided_by: dict[str, list[Mapping[str, Any]]] = {}
    for package in by_name.values():
        provides = package.get("provides")
        if not isinstance(provides, list):
            raise SystemExit(f"locked package provides must be a list: {package['name']}")
        for raw_provide in provides:
            alternative = parse_dependency_alternative(str(raw_provide))
            if alternative is not None:
                provided_by.setdefault(alternative.name, []).append(package)

    missing_roots = set(ROOT_PACKAGES) - set(by_name)
    if missing_roots:
        raise SystemExit(f"missing root package(s): {sorted(missing_roots)}")

    for package in by_name.values():
        for field_name in ("pre_depends", "depends"):
            relation_groups = package.get(field_name)
            if not isinstance(relation_groups, list):
                raise SystemExit(f"locked package {field_name} must be a list: {package['name']}")
            for relation_group in relation_groups:
                if not dependency_is_satisfied(str(relation_group), by_name, provided_by):
                    raise SystemExit(
                        f"unresolved locked dependency for {package['name']}: {relation_group}"
                    )


def dependency_is_satisfied(
    relation_group: str,
    by_name: Mapping[str, Mapping[str, Any]],
    provided_by: Mapping[str, Sequence[Mapping[str, Any]]],
) -> bool:
    for raw_alternative in relation_group.split("|"):
        alternative = parse_dependency_alternative(raw_alternative)
        if alternative is None:
            continue
        package = by_name.get(alternative.name)
        if package is not None and record_satisfies(package, alternative):
            return True
        for provider in provided_by.get(alternative.name, ()):
            if record_satisfies(provider, alternative):
                return True
    return False


def verify_package_records(
    lock: Mapping[str, Any],
    records_by_index: Mapping[str, Mapping[str, PackageRecord]],
) -> None:
    for package in packages_by_name(lock).values():
        source_index_id = str(package["source_index_id"])
        records = records_by_index[source_index_id]
        matched = [
            record
            for record in records.values()
            if record.name == package["name"]
            and record.version == package["version"]
            and record.architecture == package["architecture"]
            and record.filename == package["filename"]
        ]
        if len(matched) != 1:
            raise SystemExit(f"locked package record not found in signed index: {package['name']}")
        record = matched[0]
        expected = package_to_lock_record(record)
        if package != expected:
            raise SystemExit(f"locked package drift: {package['name']}")


def verify_lock_against_signed_metadata(*, lock_path: Path, keyring: Path) -> dict[str, Any]:
    lock = read_json(lock_path)
    with tempfile.TemporaryDirectory(prefix="tuntun-openssh-metadata-") as tmp:
        _origins, _indexes, records_by_index = fetch_verified_metadata(
            lock=lock,
            keyring=keyring,
            work_root=Path(tmp),
        )
    verify_package_records(lock, records_by_index)
    verify_complete_dependency_closure(lock)
    return lock


def download_packages(lock: Mapping[str, Any], *, download_root: Path) -> None:
    download_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    for package in packages_by_name(lock).values():
        filename = Path(str(package["filename"])).name
        target = download_root / filename
        raw = fetch_url(str(package["url"]), max_bytes=int(package["size_bytes"]))
        if len(raw) != package["size_bytes"]:
            raise SystemExit(f"download size mismatch: {package['name']}")
        if sha256_bytes(raw) != package["sha256"]:
            raise SystemExit(f"download digest mismatch: {package['name']}")
        target.write_bytes(raw)
    write_json(
        download_root / "download-manifest.json",
        {
            "schema_version": LOCK_SCHEMA_VERSION,
            "packages": [
                {
                    "name": package["name"],
                    "version": package["version"],
                    "filename": Path(str(package["filename"])).name,
                    "sha256": package["sha256"],
                }
                for package in packages_by_name(lock).values()
            ],
        },
    )


def verify_downloaded_packages(lock: Mapping[str, Any], *, download_root: Path) -> None:
    for package in packages_by_name(lock).values():
        path = download_root / Path(str(package["filename"])).name
        raw = path.read_bytes()
        if len(raw) != package["size_bytes"]:
            raise SystemExit(f"downloaded size mismatch: {package['name']}")
        if sha256_bytes(raw) != package["sha256"]:
            raise SystemExit(f"downloaded digest mismatch: {package['name']}")


def package_install_order(lock: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    by_name = packages_by_name(lock)
    provided_by: dict[str, list[str]] = {}
    for package in by_name.values():
        for provided in package["provides"]:
            alternative = parse_dependency_alternative(str(provided))
            if alternative is not None:
                provided_by.setdefault(alternative.name, []).append(str(package["name"]))

    ordered: list[str] = []
    temporary: set[str] = set()
    permanent: set[str] = set()

    def selected_dependency_name(relation_group: str) -> str | None:
        for raw_alternative in relation_group.split("|"):
            alternative = parse_dependency_alternative(raw_alternative)
            if alternative is None:
                continue
            package = by_name.get(alternative.name)
            if package is not None and record_satisfies(package, alternative):
                return alternative.name
            for provider_name in provided_by.get(alternative.name, ()):
                provider = by_name[provider_name]
                if record_satisfies(provider, alternative):
                    return provider_name
        return None

    def visit(package_name: str) -> None:
        if package_name in permanent:
            return
        if package_name in temporary:
            return
        temporary.add(package_name)
        package = by_name[package_name]
        for field_name in ("pre_depends", "depends"):
            for relation_group in package[field_name]:
                dependency_name = selected_dependency_name(str(relation_group))
                if dependency_name is not None and dependency_name in by_name:
                    visit(dependency_name)
        temporary.remove(package_name)
        permanent.add(package_name)
        ordered.append(package_name)

    for package_name in sorted(by_name):
        visit(package_name)
    return [by_name[name] for name in ordered]


def install_packages(lock: Mapping[str, Any], *, download_root: Path) -> None:
    verify_downloaded_packages(lock, download_root=download_root)
    paths = [
        str(download_root / Path(str(package["filename"])).name)
        for package in package_install_order(lock)
    ]
    subprocess.run(["dpkg", "-i", *paths], check=True)


def verify_installed_packages(lock: Mapping[str, Any]) -> None:
    for package in packages_by_name(lock).values():
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}", str(package["name"])],
            check=True,
            capture_output=True,
            text=True,
        )
        if result.stdout != package["version"]:
            raise SystemExit(
                f"installed package version mismatch: {package['name']} "
                f"{result.stdout!r} != {package['version']!r}"
            )
    for binary in ("/usr/bin/ssh", "/usr/sbin/sshd"):
        if not Path(binary).is_file() or not os.access(binary, os.X_OK):
            raise SystemExit(f"missing executable OpenSSH binary: {binary}")
    subprocess.run(["/usr/bin/ssh", "-V"], check=True, capture_output=True)
    subprocess.run(["/usr/sbin/sshd", "-V"], check=True, capture_output=True)


def _validated_bootstrap_tar_path(member: tarfile.TarInfo) -> PurePosixPath:
    name = member.name
    if (
        not isinstance(name, str)
        or not name
        or "\x00" in name
        or "\\" in name
        or name.startswith("/")
    ):
        raise SystemExit("unsafe bootstrap keyring tar member")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise SystemExit("unsafe bootstrap keyring tar member")
    return path


def _validate_bootstrap_tar_member_metadata(member: tarfile.TarInfo) -> None:
    if not (member.isfile() or member.isdir()):
        raise SystemExit("unsafe bootstrap keyring tar member")
    if member.uid != 0 or member.gid != 0:
        raise SystemExit("unsafe bootstrap keyring tar member")
    mode = member.mode
    if mode < 0 or mode > 0o7777:
        raise SystemExit("unsafe bootstrap keyring tar member")
    if mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX | 0o022):
        raise SystemExit("unsafe bootstrap keyring tar member")
    if member.isfile() and mode & 0o111:
        raise SystemExit("unsafe bootstrap keyring tar member")


def _safe_extract_bootstrap_keyring_tar(
    tar: tarfile.TarFile,
    *,
    work_root: Path,
) -> Path:
    members = tar.getmembers()
    if len(members) > BOOTSTRAP_KEYRING_MAX_TAR_MEMBERS:
        raise SystemExit("bootstrap keyring tar member count exceeded")

    seen: set[PurePosixPath] = set()
    total_size = 0
    keyring_member: tarfile.TarInfo | None = None
    for member in members:
        member_path = _validated_bootstrap_tar_path(member)
        if member_path in seen:
            raise SystemExit("duplicate bootstrap keyring tar member")
        seen.add(member_path)

        _validate_bootstrap_tar_member_metadata(member)
        if not member.isfile():
            continue
        if member.size < 0 or member.size > BOOTSTRAP_KEYRING_MAX_FILE_BYTES:
            raise SystemExit("bootstrap keyring tar member size exceeded")
        total_size += member.size
        if total_size > BOOTSTRAP_KEYRING_MAX_TOTAL_BYTES:
            raise SystemExit("bootstrap keyring tar total size exceeded")
        if member_path == BOOTSTRAP_KEYRING_TAR_PATH:
            keyring_member = member

    if keyring_member is None or keyring_member.size <= 0:
        raise SystemExit("ubuntu archive keyring missing from bootstrap package")

    extracted = tar.extractfile(keyring_member)
    if extracted is None:
        raise SystemExit("ubuntu archive keyring missing from bootstrap package")
    keyring_raw = extracted.read(keyring_member.size + 1)
    if len(keyring_raw) != keyring_member.size:
        raise SystemExit("unsafe bootstrap keyring tar member")

    keyring = work_root / Path(*BOOTSTRAP_KEYRING_TAR_PATH.parts)
    keyring.parent.mkdir(parents=True, exist_ok=True)
    keyring.write_bytes(keyring_raw)
    keyring.chmod(0o644)
    return keyring


def extract_bootstrap_keyring(*, work_root: Path) -> Path:
    deb_raw = fetch_url(BOOTSTRAP_KEYRING_URL)
    if not deb_raw.startswith(b"!<arch>\n"):
        raise SystemExit("bootstrap keyring package is not a deb archive")
    offset = 8
    while offset < len(deb_raw):
        header = deb_raw[offset : offset + 60]
        offset += 60
        name = header[:16].decode("ascii").strip().rstrip("/")
        size = int(header[48:58].decode("ascii").strip())
        body = deb_raw[offset : offset + size]
        offset += size + (size % 2)
        if name != "data.tar.zst":
            continue
        compressed = work_root / "ubuntu-keyring-data.tar.zst"
        compressed.write_bytes(body)
        tar_raw = subprocess.run(
            ["zstd", "-dc", str(compressed)],
            check=True,
            capture_output=True,
        ).stdout
        with tarfile.open(fileobj=io.BytesIO(tar_raw), mode="r:") as tar:
            keyring = _safe_extract_bootstrap_keyring_tar(tar, work_root=work_root)
        if not keyring.is_file():
            raise SystemExit("ubuntu archive keyring missing from bootstrap package")
        return keyring
    raise SystemExit("bootstrap keyring package does not contain data.tar.zst")


def resolve_keyring(args: argparse.Namespace, *, work_root: Path) -> Path:
    if args.keyring is not None:
        return cast(Path, args.keyring)
    if args.bootstrap_keyring:
        return extract_bootstrap_keyring(work_root=work_root)
    return DEFAULT_KEYRING


def command_derive_lock(args: argparse.Namespace) -> None:
    with tempfile.TemporaryDirectory(prefix="tuntun-openssh-lock-") as tmp:
        work_root = Path(tmp)
        keyring = resolve_keyring(args, work_root=work_root)
        lock = derive_lock(keyring=keyring, work_root=work_root)
    if args.output is None:
        print(json.dumps(lock, indent=2, sort_keys=False, ensure_ascii=False))
    else:
        write_json(args.output, lock)


def command_verify_download(args: argparse.Namespace) -> None:
    with tempfile.TemporaryDirectory(prefix="tuntun-openssh-lock-") as tmp:
        keyring = resolve_keyring(args, work_root=Path(tmp))
        lock = verify_lock_against_signed_metadata(lock_path=args.lock_path, keyring=keyring)
    download_packages(lock, download_root=args.download_root)


def command_install(args: argparse.Namespace) -> None:
    lock = read_json(args.lock_path)
    verify_complete_dependency_closure(lock)
    install_packages(lock, download_root=args.download_root)


def command_verify_installed(args: argparse.Namespace) -> None:
    lock = read_json(args.lock_path)
    verify_complete_dependency_closure(lock)
    verify_installed_packages(lock)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    derive = subparsers.add_parser("derive-lock")
    derive.add_argument("--output", type=Path)
    derive.add_argument("--keyring", type=Path)
    derive.add_argument("--bootstrap-keyring", action="store_true")
    derive.set_defaults(func=command_derive_lock)

    verify_download = subparsers.add_parser("verify-download")
    verify_download.add_argument("--lock-path", type=Path, default=DEFAULT_LOCK_PATH)
    verify_download.add_argument("--download-root", type=Path, required=True)
    verify_download.add_argument("--keyring", type=Path)
    verify_download.add_argument("--bootstrap-keyring", action="store_true")
    verify_download.set_defaults(func=command_verify_download)

    install = subparsers.add_parser("install")
    install.add_argument("--lock-path", type=Path, default=DEFAULT_LOCK_PATH)
    install.add_argument("--download-root", type=Path, required=True)
    install.set_defaults(func=command_install)

    verify_installed = subparsers.add_parser("verify-installed")
    verify_installed.add_argument("--lock-path", type=Path, default=DEFAULT_LOCK_PATH)
    verify_installed.set_defaults(func=command_verify_installed)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
