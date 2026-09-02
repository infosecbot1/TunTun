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

RuleText = Annotated[str, Field(min_length=1, max_length=512)]

_PROMPT_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
_PROMPT_MAX_BYTES = 65_536
_VERSION_MAX_BYTES = 8_192


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
    descriptor: int | None = None
    try:
        descriptor = os.open(path, _PROMPT_READ_FLAGS)
        before = os.fstat(descriptor)
        _require_safe_prompt_file(before)
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
                raise PermissionError("prompt control file too large")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        named = os.lstat(path)
        if (
            total != before.st_size
            or _stable_identity(before) != _stable_identity(after)
            or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise PermissionError("prompt control file changed")
        _require_safe_prompt_file(after)
        return b"".join(chunks).decode("utf-8", errors="strict").strip()
    except OSError:
        raise PermissionError("unsafe prompt control file") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _require_safe_prompt_file(value: os.stat_result) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid not in {0, os.geteuid()}
        or value.st_mode & 0o022
        or value.st_nlink != 1
    ):
        raise PermissionError("unsafe prompt control file")


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
        return (
            f"{self._base}\n"
            f"Prompt bundle SHA-256: {self.prompt_bundle_sha256}\n"
            f"{' '.join(rules)} {language_rule}"
        )
