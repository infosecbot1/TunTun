from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Annotated, Literal, cast

from pydantic import Field
from tuntun_contracts.base import ContractModel
from tuntun_contracts.identity import PersonaProjection
from tuntun_core.config.loader import read_bounded_strict_yaml
from tuntun_core.config.secure_paths import (
    _acquire_owned_descriptor,
    _close_preserving_primary,
    _require_no_unsafe_acl,
    absolute_lexical_path,
    open_trusted_directory,
)

RuleText = Annotated[str, Field(min_length=1, max_length=512)]

_PROMPT_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
_PROMPT_MAX_BYTES = 65_536
_VERSION_MAX_BYTES = 8_192
_SYSTEM_PROMPT_MAX_BYTES = 32_768
_SAFE_PROJECTION_MATRIX = frozenset(
    {
        ("owner", "general", "neutral", "brief", "none"),
        ("owner", "technical_security", "precise", "detailed", "none"),
        ("owner", "household_practical", "practical", "standard", "none"),
        ("adult", "general", "neutral", "brief", "none"),
        ("adult", "technical_security", "precise", "detailed", "none"),
        ("adult", "household_practical", "practical", "standard", "none"),
        ("k2", "early_learning", "warm", "brief", "k2"),
        ("n1", "early_learning", "warm", "brief", "n1"),
        ("guest", "general", "neutral", "brief", "none"),
    }
)


class RoleRulesV1(ContractModel):
    owner: RuleText
    adult: RuleText
    k2: RuleText
    n1: RuleText
    guest: RuleText


class ContextRulesV1(ContractModel):
    general: RuleText
    technical_security: RuleText
    household_practical: RuleText
    early_learning: RuleText


class ToneRulesV1(ContractModel):
    neutral: RuleText
    precise: RuleText
    practical: RuleText
    warm: RuleText


class DepthRulesV1(ContractModel):
    brief: RuleText
    standard: RuleText
    detailed: RuleText


class LearningRulesV1(ContractModel):
    none: RuleText
    k2: RuleText
    n1: RuleText


class PersonaRulesV1(ContractModel):
    role: RoleRulesV1
    context: ContextRulesV1
    tone: ToneRulesV1
    depth: DepthRulesV1
    learning: LearningRulesV1


class PromptVersionsV1(ContractModel):
    base: Literal[1]
    roles: Literal[1]
    persona_projection: Literal[1]
    language: Literal[1]


def _read_prompt_text(path: Path, max_bytes: int = _PROMPT_MAX_BYTES) -> str:
    if type(max_bytes) is not int or not 1 <= max_bytes <= _PROMPT_MAX_BYTES:
        raise ValueError("invalid prompt control bound")
    try:
        absolute = absolute_lexical_path(Path(path))
        with open_trusted_directory(absolute.parent) as parent:
            parent.revalidate()
            try:
                file_owner = _acquire_owned_descriptor(
                    lambda: os.open(absolute.name, _PROMPT_READ_FLAGS, dir_fd=parent.fd),
                    _close_fd,
                )
            except OSError:
                raise PermissionError("unsafe prompt control file") from None
            file_error: BaseException | None = None
            try:
                descriptor = file_owner.borrow()
                before = os.fstat(descriptor)
                named_before = os.stat(
                    absolute.name,
                    dir_fd=parent.fd,
                    follow_symlinks=False,
                )
                _require_safe_prompt_file(
                    descriptor,
                    before,
                    named_before,
                    parent_device=parent.device,
                )
                if not 1 <= before.st_size <= max_bytes:
                    raise PermissionError("unsafe prompt control file")
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = os.read(descriptor, min(65_536, max_bytes + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise PermissionError("unsafe prompt control file")
                    chunks.append(chunk)
                after = os.fstat(descriptor)
                named_after = os.stat(
                    absolute.name,
                    dir_fd=parent.fd,
                    follow_symlinks=False,
                )
                if (
                    total != before.st_size
                    or _stable_identity(before) != _stable_identity(after)
                    or (before.st_dev, before.st_ino) != (named_before.st_dev, named_before.st_ino)
                    or (after.st_dev, after.st_ino) != (named_after.st_dev, named_after.st_ino)
                    or (named_before.st_dev, named_before.st_ino)
                    != (named_after.st_dev, named_after.st_ino)
                ):
                    raise PermissionError("unsafe prompt control file")
                _require_safe_prompt_file(
                    descriptor,
                    after,
                    named_after,
                    parent_device=parent.device,
                )
                parent.revalidate()
                return b"".join(chunks).decode("utf-8", errors="strict").strip()
            except OSError:
                file_error = PermissionError("unsafe prompt control file")
                raise file_error from None
            except BaseException as error:
                file_error = error
                raise
            finally:
                _close_preserving_primary(file_owner, _close_fd, file_error)
    except PermissionError:
        raise PermissionError("unsafe prompt control file") from None
    except OSError:
        raise PermissionError("unsafe prompt control file") from None


def _close_fd(descriptor: int) -> None:
    os.close(descriptor)


def _require_safe_prompt_file(
    descriptor: int,
    opened: os.stat_result,
    named: os.stat_result,
    *,
    parent_device: int,
) -> None:
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        or opened.st_dev != parent_device
        or opened.st_uid not in {0, os.geteuid()}
        or opened.st_mode & 0o022
        or opened.st_nlink != 1
    ):
        raise PermissionError("unsafe prompt control file")
    _require_no_unsafe_acl(descriptor, "unsafe prompt control file")


def _stable_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


class PersonaBuilder:
    def __init__(
        self,
        *,
        base: str,
        rules: PersonaRulesV1,
        versions: PromptVersionsV1,
        bundle_sha256: str,
    ) -> None:
        self._base = base
        self._rules = rules
        self._versions = versions
        self.prompt_bundle_sha256 = bundle_sha256

    @classmethod
    def from_directory(cls, root: Path) -> PersonaBuilder:
        base = _read_prompt_text(root / "conversation/base.md")
        raw_rules = read_bounded_strict_yaml(
            root / "conversation/family-role-rules.yaml",
            max_bytes=_PROMPT_MAX_BYTES,
        )
        raw_versions = read_bounded_strict_yaml(
            root / "versions.yaml", max_bytes=_VERSION_MAX_BYTES
        )
        rules = PersonaRulesV1.model_validate(raw_rules, strict=True)
        versions = PromptVersionsV1.model_validate(raw_versions, strict=True)
        canonical = json.dumps(
            {
                "base": base,
                "rules": rules.model_dump(mode="python"),
                "versions": versions.model_dump(mode="python"),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return cls(
            base=base,
            rules=rules,
            versions=versions,
            bundle_sha256=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        )

    def build(self, persona: PersonaProjection, language: str) -> str:
        if type(persona) is not PersonaProjection:
            raise TypeError("persona must be an exact PersonaProjection")
        _require_safe_projection(persona)
        if type(language) is not str:
            raise TypeError("language must be an exact str")
        if language not in {"en", "hi", "hi_romanized", "hinglish"}:
            raise ValueError("unknown language mode")
        rules = (
            self._rules.role.model_dump(mode="python")[persona.role],
            self._rules.context.model_dump(mode="python")[persona.context],
            self._rules.tone.model_dump(mode="python")[persona.tone],
            self._rules.depth.model_dump(mode="python")[persona.depth],
            self._rules.learning.model_dump(mode="python")[persona.learning_level],
        )
        language_rule = {
            "en": "Reply in English.",
            "hi": "Reply in Devanagari Hindi.",
            "hi_romanized": "Reply in Romanized Hindi without switching to Devanagari.",
            "hinglish": "Follow the speaker's Hindi-English mixing naturally.",
        }[cast(Literal["en", "hi", "hi_romanized", "hinglish"], language)]
        prompt = (
            f"{self._base}\n"
            f"Prompt bundle SHA-256: {self.prompt_bundle_sha256}\n"
            f"{' '.join(rules)} {language_rule}"
        )
        if len(prompt.encode("utf-8")) > _SYSTEM_PROMPT_MAX_BYTES:
            raise ValueError("system prompt outside provider bounds")
        return prompt


def _require_safe_projection(persona: PersonaProjection) -> None:
    if (
        persona.role,
        persona.context,
        persona.tone,
        persona.depth,
        persona.learning_level,
    ) not in _SAFE_PROJECTION_MATRIX:
        raise ValueError("unsafe persona projection")
