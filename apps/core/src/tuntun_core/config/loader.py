from __future__ import annotations

import math
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import TypeAlias, cast

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from .secure_paths import (
    OwnedDirectory,
    _acquire_owned_descriptor,
    _close_preserving_primary,
    _require_no_unsafe_acl,
    absolute_lexical_path,
    open_trusted_directory,
)
from .settings import Settings

YamlValue: TypeAlias = (  # noqa: UP040 -- keep Python 3.11 syntax compatibility.
    None | bool | int | float | str | list["YamlValue"] | dict[str, "YamlValue"]
)

MAX_SETTINGS_BYTES = 262_144
MAX_YAML_BYTES = 1_048_576
OVERRIDE_NAME = re.compile(
    r"^TUNTUN_([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*)__"
    r"([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*)$"
)
READ_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW


def _open_regular_at(name: str, parent_fd: int) -> int:
    return os.open(name, READ_FLAGS, dir_fd=parent_fd)


def _stat_regular_at(name: str, parent_fd: int) -> os.stat_result:
    return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)


def _reported_file_owner(value: os.stat_result) -> int:
    return value.st_uid


def _close_fd(fd: int) -> None:
    os.close(fd)


def _validate_mapping_nodes(node: Node) -> None:
    if isinstance(node, MappingNode):
        seen: set[str] = set()
        for key_node, value_node in node.value:
            if (
                not isinstance(key_node, ScalarNode)
                or key_node.tag != "tag:yaml.org,2002:str"
                or key_node.value in seen
            ):
                raise ValueError("invalid configuration")
            seen.add(key_node.value)
            _validate_mapping_nodes(value_node)
    elif isinstance(node, SequenceNode):
        for item in node.value:
            _validate_mapping_nodes(item)
    elif not isinstance(node, ScalarNode):
        raise ValueError("invalid configuration")


def _require_yaml_value(value: object) -> YamlValue:
    if value is None or type(value) in {bool, int, str}:
        return cast(None | bool | int | str, value)
    if type(value) is float:
        number = value
        if not math.isfinite(number):
            raise ValueError("invalid configuration")
        return number
    if type(value) is list:
        values = cast(list[object], value)
        return [_require_yaml_value(item) for item in values]
    if type(value) is dict:
        mapping = cast(dict[object, object], value)
        result: dict[str, YamlValue] = {}
        for key, item in mapping.items():
            if type(key) is not str:
                raise ValueError("invalid configuration")
            result[key] = _require_yaml_value(item)
        return result
    raise ValueError("invalid configuration")


def parse_bounded_strict_yaml(
    raw: bytes,
    *,
    max_bytes: int,
    max_events: int = 16_384,
    max_depth: int = 32,
) -> YamlValue:
    if (
        type(raw) is not bytes
        or type(max_bytes) is not int
        or type(max_events) is not int
        or type(max_depth) is not int
        or not 0 <= len(raw) <= max_bytes <= MAX_YAML_BYTES
        or not 1 <= max_events <= 65_536
        or not 1 <= max_depth <= 64
    ):
        raise ValueError("invalid configuration")
    try:
        text = raw.decode("utf-8", errors="strict")
        depth = 0
        for count, event in enumerate(yaml.parse(text), start=1):
            if (
                count > max_events
                or getattr(event, "anchor", None) is not None
                or getattr(event, "tag", None) is not None
            ):
                raise ValueError("invalid configuration")
            if isinstance(event, yaml.events.AliasEvent):
                raise ValueError("invalid configuration")
            if isinstance(event, yaml.events.CollectionStartEvent):
                depth += 1
                if depth > max_depth:
                    raise ValueError("invalid configuration")
            elif isinstance(event, yaml.events.CollectionEndEvent):
                depth -= 1
        if depth != 0:
            raise ValueError("invalid configuration")
        node = yaml.compose(text, Loader=yaml.SafeLoader)
        if node is not None:
            _validate_mapping_nodes(node)
        loaded = yaml.safe_load(text)
    except (UnicodeError, yaml.YAMLError, ValueError):
        raise ValueError("invalid configuration") from None
    return _require_yaml_value(loaded)


def _require_regular_file(
    descriptor: int,
    opened: os.stat_result,
    named: os.stat_result,
    parent: OwnedDirectory,
    *,
    require_private: bool,
) -> None:
    owner = _reported_file_owner(opened)
    mode = stat.S_IMODE(opened.st_mode)
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        or opened.st_dev != parent.device
        or opened.st_nlink != 1
        or owner not in {0, os.geteuid()}
        or mode & 0o022
        or (require_private and (owner != os.geteuid() or mode != 0o600))
    ):
        raise PermissionError("unsafe configuration file")
    _require_no_unsafe_acl(descriptor, "unsafe configuration file")


def _stable_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def read_bounded_strict_yaml(
    path: Path,
    *,
    max_bytes: int = MAX_SETTINGS_BYTES,
    require_private: bool = False,
) -> YamlValue:
    if (
        type(max_bytes) is not int
        or not 0 <= max_bytes <= MAX_YAML_BYTES
        or type(require_private) is not bool
    ):
        raise ValueError("invalid configuration")
    absolute = absolute_lexical_path(Path(path))
    try:
        with open_trusted_directory(absolute.parent) as parent:
            parent.revalidate()
            try:
                file_owner = _acquire_owned_descriptor(
                    lambda: _open_regular_at(absolute.name, parent.fd),
                    _close_fd,
                )
            except OSError:
                raise PermissionError("unsafe configuration file") from None
            file_error: BaseException | None = None
            try:
                fd = file_owner.borrow()
                before = os.fstat(fd)
                named_before = _stat_regular_at(absolute.name, parent.fd)
                _require_regular_file(
                    fd,
                    before,
                    named_before,
                    parent,
                    require_private=require_private,
                )
                if before.st_size > max_bytes:
                    raise PermissionError("unsafe configuration file")
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = os.read(
                        fd,
                        min(65_536, max_bytes + 1 - total),
                    )
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError("invalid configuration")
                    chunks.append(chunk)
                after = os.fstat(fd)
                named_after = _stat_regular_at(absolute.name, parent.fd)
                parent.revalidate()
                _require_regular_file(
                    fd,
                    after,
                    named_after,
                    parent,
                    require_private=require_private,
                )
                if (
                    total != before.st_size
                    or _stable_identity(before) != _stable_identity(after)
                    or (after.st_dev, after.st_ino) != (named_after.st_dev, named_after.st_ino)
                ):
                    raise PermissionError("configuration changed during read")
                raw = b"".join(chunks)
            except BaseException as error:
                file_error = error
                raise
            finally:
                try:
                    _close_preserving_primary(file_owner, _close_fd, file_error)
                except Exception:
                    raise PermissionError("unsafe configuration file") from None
    except PermissionError:
        raise
    except OSError:
        raise PermissionError("unsafe configuration file") from None
    return parse_bounded_strict_yaml(raw, max_bytes=max_bytes)


def load_settings(
    yaml_path: Path | None,
    environ: Mapping[str, str],
) -> Settings:
    data: dict[str, object] = {}
    if yaml_path is not None:
        loaded = read_bounded_strict_yaml(
            yaml_path,
            require_private=True,
        )
        if type(loaded) is not dict:
            raise ValueError("configuration root must be a mapping")
        data = Settings.model_validate(loaded).model_dump(mode="python")
    for name, raw_value in environ.items():
        if type(name) is not str or type(raw_value) is not str:
            raise ValueError("invalid TUNTUN override")
        if not name.startswith("TUNTUN_"):
            continue
        match = OVERRIDE_NAME.fullmatch(name)
        if match is None:
            raise ValueError(f"invalid TUNTUN override: {name}")
        encoded = raw_value.encode("utf-8", errors="strict")
        value = parse_bounded_strict_yaml(
            encoded,
            max_bytes=1_024,
            max_events=8,
            max_depth=1,
        )
        if isinstance(value, (dict, list)) or value is None:
            raise ValueError(f"invalid TUNTUN override: {name}")
        section, key = (part.lower() for part in match.groups())
        if section in data:
            existing = data[section]
            if type(existing) is not dict:
                raise ValueError(f"invalid TUNTUN override: {name}")
            nested = dict(cast(dict[str, object], existing))
        else:
            nested = {}
        nested[key] = value
        data[section] = nested
    return Settings.model_validate(data)
