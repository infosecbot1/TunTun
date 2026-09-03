# mypy: disable-error-code="no-untyped-def"
from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from tuntun_contracts.identity import PersonaTraits
from tuntun_core.adapters.sqlcipher.profile_crypto import ProfileCrypto
from tuntun_core.domain.profile import ProfileClass, UpdatePersonaTraits
from tuntun_core.services.actions.parameter_binding import ActionBindingVerifier
from tuntun_core.services.identity.consent import ConsentDenied
from tuntun_core.services.identity.profiles import StaleProfileVersion, require_fresh_passkey

from tests.identity_support import (
    _persona_command,
    _profile_create_command,
    _revoke_profile_command,
)


def test_profile_consent_receipt_inventory_is_bounded_and_unique(profile_factory) -> None:
    schema = profile_factory.model_type.model_json_schema()["properties"][
        "current_consent_receipt_ids"
    ]

    assert schema["maxItems"] == 8
    with pytest.raises(ValueError):
        profile_factory(current_consent_receipt_ids=profile_factory.nine_receipt_ids())
    receipt = profile_factory.receipt_id()
    with pytest.raises(ValueError):
        profile_factory(current_consent_receipt_ids=(receipt, receipt))


def test_profile_crypto_rejects_key_id_substitution_and_prefix_tamper() -> None:
    crypto = ProfileCrypto(b"x" * 32, key_id="profile-aead-v1")
    household_id = uuid4()
    subject_id = uuid4()
    traits = PersonaTraits(
        context="technical_security",
        tone="precise",
        depth="detailed",
        learning_level="none",
    )
    sealed = crypto.seal_traits(household_id, subject_id, 1, traits)

    with pytest.raises(PermissionError, match="encrypted_persona_traits_invalid"):
        ProfileCrypto(b"x" * 32, key_id="other-profile-key").open_traits(
            household_id,
            subject_id,
            1,
            sealed,
        )

    tampered = bytearray(sealed)
    tampered[len(b"TTPROF-TRAITS-V1\0") + 2] ^= 1
    with pytest.raises(PermissionError, match="encrypted_persona_traits_invalid"):
        crypto.open_traits(household_id, subject_id, 1, bytes(tampered))


def test_profile_crypto_rejects_bad_root_key_id_and_truncated_record_envelopes() -> None:
    with pytest.raises(ValueError, match="root key id"):
        ProfileCrypto(b"x" * 32, key_id="perfil-ñ")
    with pytest.raises(ValueError, match="root key id"):
        ProfileCrypto(b"x" * 32, key_id="k" * 129)

    crypto = ProfileCrypto(b"x" * 32, key_id="kid")
    household_id = uuid4()
    subject_id = uuid4()
    sealed = crypto.seal_traits(
        household_id,
        subject_id,
        1,
        PersonaTraits(
            context="technical_security",
            tone="precise",
            depth="detailed",
            learning_level="none",
        ),
    )
    magic_length = len(b"TTPROF-TRAITS-V1\0")
    for truncated in (
        sealed[:magic_length],
        sealed[: magic_length + 1],
        sealed[: magic_length + 2 + len("kid") + 11],
        sealed[: magic_length + 2 + len("kid") + 12 + 12 + 47],
    ):
        with pytest.raises(PermissionError, match="encrypted_persona_traits_invalid"):
            crypto.open_traits(household_id, subject_id, 1, truncated)


def test_profile_crypto_binds_household_version_and_purpose_to_record_envelope() -> None:
    crypto = ProfileCrypto(b"x" * 32, key_id="profile-aead-v1")
    household_id = uuid4()
    subject_id = uuid4()
    traits = PersonaTraits(
        context="technical_security",
        tone="precise",
        depth="detailed",
        learning_level="none",
    )
    sealed = crypto.seal_traits(household_id, subject_id, 3, traits)

    assert crypto.open_traits(household_id, subject_id, 3, sealed) == traits
    for other_household, other_version, tamper in (
        (uuid4(), 3, None),
        (household_id, 4, None),
        (household_id, 3, bytearray(b"TTPROF-DISPLAY-V1\0") + sealed[len(b"TTPROF-TRAITS-V1\0") :]),
    ):
        envelope = sealed if tamper is None else bytes(tamper)
        with pytest.raises(PermissionError, match="encrypted_persona_traits_invalid"):
            crypto.open_traits(other_household, subject_id, other_version, envelope)

    tampered_schema = bytearray(sealed)
    tampered_schema[len(b"TTPROF-TRAITS-V1\0")] ^= 1
    with pytest.raises(PermissionError, match="encrypted_persona_traits_invalid"):
        crypto.open_traits(household_id, subject_id, 3, bytes(tampered_schema))


def test_future_passkey_consumed_at_is_rejected(
    bound_profile_command_factory,
    passkey_auth_factory,
    now,
) -> None:
    command = bound_profile_command_factory(operation="create")
    auth = passkey_auth_factory(command.action_binding).model_copy(
        update={"consumed_at": now + timedelta(seconds=1)}
    )

    with pytest.raises(PermissionError, match="fresh_passkey_required"):
        require_fresh_passkey(
            auth,
            command.action_binding,
            now,
            ActionBindingVerifier(),
        )


@pytest.mark.asyncio
async def test_guest_is_projection_not_persisted(
    profile_service,
    profile_repository,
    household_id,
) -> None:
    projection = await profile_service.get_projection(household_id, None)

    assert projection.profile_class is ProfileClass.GUEST
    assert await profile_repository.count_subjects(household_id) == 0


@pytest.mark.asyncio
async def test_active_profile_projection_and_current_active_guard_preserve_subject_class(
    profile_service,
    mutation_scope,
    adult_a,
) -> None:
    projection = await profile_service.get_projection(adult_a.household_id, adult_a.id)

    assert projection.subject_id == adult_a.id
    assert projection.profile_class is ProfileClass.ADULT
    assert projection.may_retrieve_private_memory is False
    async with mutation_scope.open() as uow:
        current = await profile_service.require_current_active_in_uow(
            uow,
            adult_a.household_id,
            adult_a.id,
        )
        await uow.rollback()

    assert current.id == adult_a.id


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["inactive", "revoked"])
async def test_current_active_guard_rejects_inactive_or_revoked_subject(
    identity_env,
    profile_service,
    mutation_scope,
    state,
) -> None:
    profile = identity_env.profile_factory(ProfileClass.ADULT, name=f"active-guard-{state}")
    if state == "inactive":
        profile = profile.model_copy(update={"active": False})
    else:
        profile = profile.model_copy(
            update={"active": False, "revoked_at": identity_env.clock.now()}
        )
    identity_env.profiles[profile.id] = profile

    async with mutation_scope.open() as uow:
        with pytest.raises(PermissionError, match="current_active_subject_required"):
            await profile_service.require_current_active_in_uow(
                uow,
                profile.household_id,
                profile.id,
            )
        await uow.rollback()


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["missing", "inactive", "revoked"])
async def test_unresolved_or_stale_subject_is_guest_for_all_read_projections(
    profile_service,
    profile_repository,
    household_id,
    now,
    state,
) -> None:
    subject_id = await profile_repository.subject_in_state(household_id, state)

    assert (
        await profile_service.get_projection(household_id, subject_id)
    ).profile_class is ProfileClass.GUEST
    assert (
        await profile_service.current_policy_class(household_id, subject_id) is ProfileClass.GUEST
    )
    assert (
        await profile_service.get_persona_projection(household_id, subject_id, now)
    ).role == "guest"


@pytest.mark.asyncio
async def test_projection_does_not_turn_database_failure_into_guest(
    profile_service,
    profile_repository,
    household_id,
    now,
) -> None:
    profile_repository.fail_optional_read(RuntimeError("sqlcipher_unavailable"))

    with pytest.raises(RuntimeError, match="sqlcipher_unavailable"):
        await profile_service.get_persona_projection(
            household_id,
            profile_repository.any_subject_id,
            now,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("profile_class", "learning_level"),
    [(ProfileClass.K2, "k2"), (ProfileClass.N1, "n1")],
)
async def test_missing_or_revoked_personalization_keeps_child_safety_class(
    profile_service,
    child_without_personalization_consent_factory,
    profile_class,
    learning_level,
    now,
) -> None:
    child = child_without_personalization_consent_factory(
        profile_class,
        encrypted_custom_traits=True,
    )

    projection = await profile_service.get_persona_projection(child.household_id, child.id, now)

    assert projection.model_dump() == {
        "role": profile_class.value,
        "context": "early_learning",
        "tone": "warm",
        "depth": "brief",
        "learning_level": learning_level,
    }


@pytest.mark.asyncio
async def test_missing_personalization_uses_neutral_adult_defaults_not_guest(
    profile_service,
    adult_without_personalization_consent,
    now,
) -> None:
    projection = await profile_service.get_persona_projection(
        adult_without_personalization_consent.household_id,
        adult_without_personalization_consent.id,
        now,
    )

    assert projection.model_dump() == {
        "role": "adult",
        "context": "general",
        "tone": "neutral",
        "depth": "standard",
        "learning_level": "none",
    }


@pytest.mark.asyncio
async def test_adult_replaces_and_clears_only_own_encrypted_persona(
    identity_mutations,
    profile_service,
    adult_a,
    adult_a_persona_grant,
    adult_a_clear_grant,
    sqlcipher_raw_scan,
    now,
) -> None:
    traits = PersonaTraits(
        context="technical_security",
        tone="precise",
        depth="detailed",
        learning_level="none",
    )
    updated = await identity_mutations.update_persona_traits(
        UpdatePersonaTraits(
            subject_id=adult_a.id,
            actor_id=adult_a.id,
            target_profile_class=adult_a.profile_class,
            traits=traits,
            expected_version=adult_a.version,
            action_binding=adult_a_persona_grant.binding,
        ),
        adult_a_persona_grant.id,
    )

    assert updated.version == adult_a.version + 1
    assert updated.encrypted_persona_traits is not None
    assert sqlcipher_raw_scan.contains_any(("technical_security", "precise", "detailed")) is False
    projection = await profile_service.get_persona_projection(adult_a.household_id, adult_a.id, now)
    assert projection.model_dump() == {
        "role": "adult",
        "context": "technical_security",
        "tone": "precise",
        "depth": "detailed",
        "learning_level": "none",
    }

    cleared = await identity_mutations.update_persona_traits(
        UpdatePersonaTraits(
            subject_id=adult_a.id,
            actor_id=adult_a.id,
            target_profile_class=adult_a.profile_class,
            traits=None,
            expected_version=updated.version,
            action_binding=adult_a_clear_grant.binding,
        ),
        adult_a_clear_grant.id,
    )
    assert cleared.version == updated.version + 1
    assert cleared.encrypted_persona_traits is None


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["replace", "clear"])
async def test_owner_cannot_impersonate_another_adult_persona(
    identity_mutations,
    adult_b_persona_command_factory,
    owner_grant_factory,
    operation,
) -> None:
    command = adult_b_persona_command_factory(actor="owner", operation=operation)
    grant = owner_grant_factory(command.action_binding)

    with pytest.raises(PermissionError, match="profile_persona_subject_authority_required"):
        await identity_mutations.update_persona_traits(command, grant.id)


@pytest.mark.asyncio
async def test_adult_profile_create_requires_authenticated_current_owner(
    identity_env,
    identity_mutations,
    adult_a,
) -> None:
    command = _profile_create_command(
        identity_env,
        actor_id=adult_a.id,
        profile_class=ProfileClass.ADULT,
    )
    grant = identity_env.grant_for(adult_a.id, command.action_binding)

    with pytest.raises(PermissionError, match="current_owner_authority_required"):
        await identity_mutations.create_profile(command, grant.id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method_name", "operation"),
    [
        ("create_in_uow", "create"),
        ("update_persona_traits_in_uow", "update_persona_traits"),
        ("revoke_in_uow", "revoke"),
    ],
)
async def test_profile_in_uow_methods_reject_cross_scope_uow_before_mutation(
    identity_env,
    profile_service,
    mutation_scope,
    bound_profile_command_factory,
    passkey_auth_factory,
    profile_repository_spy,
    method_name,
    operation,
) -> None:
    command = bound_profile_command_factory(operation=operation)
    auth = passkey_auth_factory(command.action_binding)

    async with mutation_scope.open() as active_uow:
        async with identity_env.uow_factory() as other_uow:
            assert active_uow is not other_uow
            with pytest.raises(RuntimeError, match="profile_uow_scope_mismatch"):
                await getattr(profile_service, method_name)(other_uow, command, auth)
            await other_uow.rollback()
        await active_uow.rollback()

    assert profile_repository_spy.read_count == 0 and profile_repository_spy.write_count == 0


@pytest.mark.asyncio
async def test_profile_create_update_and_revoke_in_uow_use_active_scope(
    identity_env,
    profile_service,
    mutation_scope,
    passkey_auth_factory,
    adult_a,
    adult_b,
) -> None:
    create_command = _profile_create_command(identity_env, profile_class=ProfileClass.ADULT)
    async with mutation_scope.open() as uow:
        created = await profile_service.create_in_uow(
            uow,
            create_command,
            passkey_auth_factory(create_command.action_binding),
        )
        await uow.commit()

    traits = PersonaTraits(
        context="household_practical",
        tone="practical",
        depth="standard",
        learning_level="none",
    )
    update_command = _persona_command(identity_env, adult_a, adult_a.id, traits)
    async with mutation_scope.open() as uow:
        updated = await profile_service.update_persona_traits_in_uow(
            uow,
            update_command,
            passkey_auth_factory(update_command.action_binding),
        )
        await uow.commit()

    revoke_command = _revoke_profile_command(identity_env, adult_b)
    async with mutation_scope.open() as uow:
        revoked = await profile_service.revoke_in_uow(
            uow,
            revoke_command,
            passkey_auth_factory(revoke_command.action_binding),
        )
        await uow.commit()

    assert created.id == create_command.subject_id
    assert updated.encrypted_persona_traits is not None
    assert revoked.active is False
    assert revoked.authority_generation == adult_b.authority_generation + 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("profile_class", "guardian_id", "expected_error"),
    [
        (ProfileClass.OWNER, None, "ordinary_profile_create_owner_forbidden"),
        (ProfileClass.ADULT, "owner", "adult_profile_guardian_forbidden"),
    ],
)
async def test_profile_create_rejects_owner_creation_and_adult_guardian_lineage(
    identity_env,
    identity_mutations,
    owner,
    profile_class,
    guardian_id,
    expected_error,
) -> None:
    command = _profile_create_command(
        identity_env,
        profile_class=profile_class,
        guardian_id=owner.id if guardian_id == "owner" else None,
    )
    grant = identity_env.grant_for(owner.id, command.action_binding)

    with pytest.raises(PermissionError, match=expected_error):
        await identity_mutations.create_profile(command, grant.id)


@pytest.mark.asyncio
async def test_child_profile_create_requires_authenticated_actor_to_be_current_owner_guardian(
    identity_env,
    identity_mutations,
    owner,
    adult_a,
) -> None:
    command = _profile_create_command(
        identity_env,
        actor_id=adult_a.id,
        profile_class=ProfileClass.K2,
        guardian_id=owner.id,
    )
    grant = identity_env.grant_for(adult_a.id, command.action_binding)

    with pytest.raises(PermissionError, match="current_owner_guardian_required"):
        await identity_mutations.create_profile(command, grant.id)


@pytest.mark.asyncio
async def test_one_adult_cannot_revoke_another_profile_without_owner_authority(
    identity_env,
    identity_mutations,
    adult_a,
    adult_b,
) -> None:
    command = _revoke_profile_command(identity_env, adult_a, actor_id=adult_b.id)
    grant = identity_env.grant_for(adult_b.id, command.action_binding)

    with pytest.raises(PermissionError, match="profile_revoke_authority_required"):
        await identity_mutations.revoke_profile(command, grant.id)


@pytest.mark.asyncio
async def test_current_owner_can_revoke_another_adult_profile(
    identity_env,
    identity_mutations,
    owner,
    adult_b,
) -> None:
    command = _revoke_profile_command(identity_env, adult_b, actor_id=owner.id)
    grant = identity_env.grant_for(owner.id, command.action_binding)

    revoked = await identity_mutations.revoke_profile(command, grant.id)

    assert revoked.active is False
    assert revoked.revoked_at == identity_env.clock.now()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "expected_error"),
    [
        ("non_guardian_actor", "profile_revoke_authority_required"),
        ("stale_guardian_generation", "profile_revoke_authority_required"),
    ],
)
async def test_child_profile_revoke_requires_current_owner_guardian_lineage(
    identity_env,
    identity_mutations,
    owner,
    adult_a,
    failure,
    expected_error,
) -> None:
    child = identity_env.profile_factory(
        ProfileClass.K2,
        name=f"child-revoke-{failure}",
        guardian_id=owner.id,
    )
    actor_id = owner.id
    if failure == "non_guardian_actor":
        actor_id = adult_a.id
    else:
        child = child.model_copy(update={"guardian_generation": child.guardian_generation + 1})
        identity_env.profiles[child.id] = child
    command = _revoke_profile_command(identity_env, child, actor_id=actor_id)
    grant = identity_env.grant_for(actor_id, command.action_binding)

    with pytest.raises(PermissionError, match=expected_error):
        await identity_mutations.revoke_profile(command, grant.id)


@pytest.mark.asyncio
async def test_current_owner_guardian_can_revoke_child_profile(
    identity_env,
    identity_mutations,
    owner,
) -> None:
    child = identity_env.profile_factory(
        ProfileClass.N1,
        name="child-revoke-current-owner",
        guardian_id=owner.id,
    )
    command = _revoke_profile_command(identity_env, child, actor_id=owner.id)
    grant = identity_env.grant_for(owner.id, command.action_binding)

    revoked = await identity_mutations.revoke_profile(command, grant.id)

    assert revoked.active is False
    assert revoked.authority_generation == child.authority_generation + 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("profile_class", "learning_level"),
    [(ProfileClass.K2, "k2"), (ProfileClass.N1, "n1")],
)
async def test_current_guardian_can_set_only_child_safe_age_learning_persona(
    identity_mutations,
    child_profile_factory,
    guardian_persona_grant_factory,
    profile_class,
    learning_level,
) -> None:
    child = child_profile_factory(profile_class)
    valid = PersonaTraits(
        context="early_learning",
        tone="warm",
        depth="brief",
        learning_level=learning_level,
    )
    grant = guardian_persona_grant_factory(child, valid)
    updated = await identity_mutations.update_persona_traits(
        UpdatePersonaTraits(
            subject_id=child.id,
            actor_id=child.guardian_id,
            target_profile_class=child.profile_class,
            traits=valid,
            expected_version=child.version,
            guardian_generation=child.guardian_generation,
            action_binding=grant.binding,
        ),
        grant.id,
    )

    assert updated.version == child.version + 1
    invalid = PersonaTraits(
        context="technical_security",
        tone="precise",
        depth="detailed",
        learning_level=learning_level,
    )
    invalid_grant = guardian_persona_grant_factory(updated, invalid)
    with pytest.raises(PermissionError, match="child_persona_traits_invalid"):
        await identity_mutations.update_persona_traits(
            UpdatePersonaTraits(
                subject_id=child.id,
                actor_id=child.guardian_id,
                target_profile_class=updated.profile_class,
                traits=invalid,
                expected_version=updated.version,
                guardian_generation=updated.guardian_generation,
                action_binding=invalid_grant.binding,
            ),
            invalid_grant.id,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "guardian_state",
    ["missing", "cross_household", "inactive", "revoked", "non_owner"],
)
async def test_child_profile_create_requires_current_active_same_household_owner_guardian(
    identity_env,
    identity_mutations,
    guardian_state,
) -> None:
    if guardian_state == "missing":
        guardian_id = uuid4()
    else:
        guardian = identity_env.profile_factory(
            ProfileClass.ADULT if guardian_state == "non_owner" else ProfileClass.OWNER,
            name=f"create-guardian-{guardian_state}-{uuid4()}",
        )
        if guardian_state == "cross_household":
            guardian = guardian.model_copy(update={"household_id": uuid4()})
        elif guardian_state == "inactive":
            guardian = guardian.model_copy(update={"active": False})
        elif guardian_state == "revoked":
            guardian = guardian.model_copy(
                update={"active": False, "revoked_at": identity_env.clock.now()}
            )
        identity_env.profiles[guardian.id] = guardian
        guardian_id = guardian.id
    command = _profile_create_command(
        identity_env,
        profile_class=ProfileClass.K2,
        guardian_id=guardian_id,
    )
    grant = identity_env.grant_for(identity_env.owner.id, command.action_binding)

    with pytest.raises(PermissionError, match="current_owner_guardian_required"):
        await identity_mutations.create_profile(command, grant.id)


@pytest.mark.asyncio
async def test_child_profile_create_records_current_owner_generation(
    identity_env,
    identity_mutations,
) -> None:
    owner = identity_env.owner.model_copy(update={"authority_generation": 7})
    identity_env.profiles[owner.id] = owner
    identity_env.current_owner_generation = 7
    command = _profile_create_command(
        identity_env,
        profile_class=ProfileClass.K2,
        guardian_id=owner.id,
    )
    grant = identity_env.grant_for(owner.id, command.action_binding)

    child = await identity_mutations.create_profile(command, grant.id)

    assert child.guardian_id == owner.id
    assert child.guardian_generation == 7


@pytest.mark.asyncio
@pytest.mark.parametrize("profile_class", [ProfileClass.K2, ProfileClass.N1])
async def test_current_guardian_can_clear_child_persona_with_exact_generation(
    identity_mutations,
    child_profile_factory,
    guardian_persona_grant_factory,
    profile_class,
) -> None:
    child = child_profile_factory(profile_class, encrypted_custom_traits=True)
    grant = guardian_persona_grant_factory(child, None)

    cleared = await identity_mutations.update_persona_traits(
        UpdatePersonaTraits(
            subject_id=child.id,
            actor_id=child.guardian_id,
            target_profile_class=child.profile_class,
            traits=None,
            expected_version=child.version,
            guardian_generation=child.guardian_generation,
            action_binding=grant.binding,
        ),
        grant.id,
    )

    assert cleared.version == child.version + 1
    assert cleared.encrypted_persona_traits is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("profile_class", "learning_level"),
    [(ProfileClass.K2, "k2"), (ProfileClass.N1, "n1")],
)
@pytest.mark.parametrize("operation", ["replace", "clear"])
async def test_child_persona_guardian_generation_substitution_fails_before_profile_read(
    identity_mutations,
    child_profile_factory,
    guardian_persona_grant_factory,
    profile_repository_spy,
    profile_class,
    learning_level,
    operation,
) -> None:
    child = child_profile_factory(profile_class)
    traits = (
        PersonaTraits(
            context="early_learning",
            tone="warm",
            depth="brief",
            learning_level=learning_level,
        )
        if operation == "replace"
        else None
    )
    grant = guardian_persona_grant_factory(child, traits)
    command = UpdatePersonaTraits(
        subject_id=child.id,
        actor_id=child.guardian_id,
        target_profile_class=child.profile_class,
        traits=traits,
        expected_version=child.version,
        guardian_generation=child.guardian_generation,
        action_binding=grant.binding,
    )
    assert command.guardian_generation is not None
    substituted = command.model_copy(
        update={"guardian_generation": command.guardian_generation + 1}
    )

    with pytest.raises(PermissionError, match="action_parameter_commitment_mismatch"):
        await identity_mutations.update_persona_traits(substituted, grant.id)

    assert profile_repository_spy.read_count == 0 and profile_repository_spy.write_count == 0


@pytest.mark.asyncio
async def test_stale_profile_version_or_stale_guardian_cannot_change_persona(
    identity_mutations,
    stale_persona_commands,
) -> None:
    for command, grant, reason in stale_persona_commands:
        with pytest.raises((PermissionError, StaleProfileVersion), match=reason):
            await identity_mutations.update_persona_traits(command, grant.id)


@pytest.mark.asyncio
async def test_adult_persona_rejects_child_learning_level_even_with_valid_consent(
    identity_env,
    identity_mutations,
    adult_a,
) -> None:
    invalid_traits = PersonaTraits(
        context="household_practical",
        tone="warm",
        depth="standard",
        learning_level="k2",
    )
    command = _persona_command(identity_env, adult_a, adult_a.id, invalid_traits)
    grant = identity_env.grant_for(adult_a.id, command.action_binding)

    with pytest.raises(PermissionError, match="adult_persona_learning_level_invalid"):
        await identity_mutations.update_persona_traits(command, grant.id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("operation", "field"),
    [
        ("create", "household_id"),
        ("create", "subject_id"),
        ("create", "profile_class"),
        ("create", "guardian_id"),
        ("create", "encrypted_display_label"),
        ("update_persona_traits", "traits"),
        ("update_persona_traits", "target_profile_class"),
        ("update_persona_traits", "expected_version"),
        ("update_persona_traits", "guardian_generation"),
        ("revoke", "subject_id"),
        ("revoke", "expected_version"),
    ],
)
async def test_profile_command_substitution_cannot_reuse_valid_grant(
    profile_service,
    bound_profile_command_factory,
    passkey_auth_factory,
    profile_repository_spy,
    operation,
    field,
) -> None:
    command = bound_profile_command_factory(operation=operation)
    auth = passkey_auth_factory(command.action_binding)
    substituted = bound_profile_command_factory(
        operation=operation,
        changed_field=field,
        keep_binding=command.action_binding,
    )

    with pytest.raises(
        PermissionError,
        match="action_binding_scope_mismatch|action_parameter_commitment_mismatch",
    ):
        await getattr(profile_service, operation)(substituted, auth)

    assert profile_repository_spy.read_count == 0 and profile_repository_spy.write_count == 0


@pytest.mark.asyncio
async def test_replace_requires_personalization_consent_but_authorized_clear_remains_available(
    identity_mutations,
    adult_without_personalization_consent,
    replace_persona_grant,
    clear_persona_grant,
) -> None:
    traits = PersonaTraits(
        context="household_practical",
        tone="practical",
        depth="standard",
        learning_level="none",
    )

    with pytest.raises(ConsentDenied, match="current_consent_required"):
        await identity_mutations.update_persona_traits(
            UpdatePersonaTraits(
                subject_id=adult_without_personalization_consent.id,
                actor_id=adult_without_personalization_consent.id,
                target_profile_class=adult_without_personalization_consent.profile_class,
                traits=traits,
                expected_version=adult_without_personalization_consent.version,
                action_binding=replace_persona_grant.binding,
            ),
            replace_persona_grant.id,
        )

    cleared = await identity_mutations.update_persona_traits(
        UpdatePersonaTraits(
            subject_id=adult_without_personalization_consent.id,
            actor_id=adult_without_personalization_consent.id,
            target_profile_class=adult_without_personalization_consent.profile_class,
            traits=None,
            expected_version=adult_without_personalization_consent.version,
            action_binding=clear_persona_grant.binding,
        ),
        clear_persona_grant.id,
    )
    assert cleared.encrypted_persona_traits is None
