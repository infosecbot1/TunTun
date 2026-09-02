from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from tuntun_contracts.identity import PersonaProjection
from tuntun_core.services.persona_builder import PersonaBuilder


def test_child_persona_contains_no_identity_or_adult_private_fact() -> None:
    persona = PersonaProjection(
        role="n1",
        context="early_learning",
        tone="warm",
        depth="brief",
        learning_level="n1",
    )

    prompt = PersonaBuilder.from_directory(Path("prompts")).build(
        persona=persona, language="hinglish"
    )

    assert "n1" not in prompt.casefold()
    assert "private adult" not in prompt.lower()
    assert "very short" in prompt.lower()


def test_projection_is_exact_and_contains_no_identifier_or_free_form_trait() -> None:
    persona = PersonaProjection(
        role="adult",
        context="technical_security",
        tone="precise",
        depth="detailed",
        learning_level="none",
    )

    assert tuple(persona.model_fields) == ("role", "context", "tone", "depth", "learning_level")
    prompt = PersonaBuilder.from_directory(Path("prompts")).build(persona=persona, language="en")

    assert "security architecture" in prompt.lower()
    assert "detailed" in prompt.lower()


def test_family_examples_exist_only_as_synthetic_configuration() -> None:
    fixture = json.loads(
        Path("fixtures/synthetic/personas/family-role-config.json").read_text(encoding="utf-8")
    )

    assert {item["example_label"] for item in fixture["examples"]} == {
        "synthetic security architect",
        "synthetic homemaker",
        "synthetic K2 learner",
        "synthetic N1 learner",
    }
    source = (
        Path("apps/core/src/tuntun_core/services/persona_builder.py")
        .read_text(encoding="utf-8")
        .casefold()
    )
    assert "security architect" not in source
    assert "homemaker" not in source


def test_prompt_files_are_the_executable_prompt_not_dead_documentation(tmp_path: Path) -> None:
    builder = PersonaBuilder.from_directory(Path("prompts"))
    prompt = builder.build(
        PersonaProjection(
            role="guest",
            context="general",
            tone="neutral",
            depth="brief",
            learning_level="none",
        ),
        language="en",
    )

    assert Path("prompts/conversation/base.md").read_text(encoding="utf-8").strip() in prompt
    assert builder.prompt_bundle_sha256 in prompt
    changed = tmp_path / "prompts"
    shutil.copytree("prompts", changed)
    (changed / "conversation/base.md").write_text("different reviewed base", encoding="utf-8")
    assert (
        PersonaBuilder.from_directory(changed).prompt_bundle_sha256 != builder.prompt_bundle_sha256
    )


@pytest.mark.parametrize(
    "mutation",
    (
        "duplicate",
        "alias",
        "tag",
        "extra",
        "oversize",
        "base_symlink",
    ),
)
def test_prompt_controls_are_exact_bounded_and_nofollow(tmp_path: Path, mutation: str) -> None:
    root = tmp_path / "prompts"
    shutil.copytree("prompts", root)
    rules = root / "conversation/family-role-rules.yaml"
    versions = root / "versions.yaml"
    if mutation == "duplicate":
        versions.write_text(versions.read_text(encoding="utf-8") + "\nbase: 1\n", encoding="utf-8")
    elif mutation == "alias":
        versions.write_text(
            "base: &v 1\nroles: *v\npersona_projection: 1\nlanguage: 1\n", encoding="utf-8"
        )
    elif mutation == "tag":
        versions.write_text(
            "base: !!int 1\nroles: 1\npersona_projection: 1\nlanguage: 1\n", encoding="utf-8"
        )
    elif mutation == "extra":
        rules.write_text(
            rules.read_text(encoding="utf-8") + "\ncaller_override: enabled\n", encoding="utf-8"
        )
    elif mutation == "oversize":
        rules.write_bytes(b"x" * 65_537)
    else:
        base = root / "conversation/base.md"
        target = root / "base.actual"
        base.replace(target)
        base.symlink_to(target)

    with pytest.raises((PermissionError, ValueError)):
        PersonaBuilder.from_directory(root)
