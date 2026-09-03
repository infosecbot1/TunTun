# mypy: disable-error-code="no-untyped-def"
from __future__ import annotations

from uuid import uuid4

import pytest
from tuntun_contracts.identity import PersonaTraits
from tuntun_contracts.policy import AssuranceLevel
from tuntun_core.domain.profile import ProfileClass
from tuntun_core.services.identity.profiles import (
    ProfileService,
    StaleProfileVersion,
    require_fresh_passkey,
)

from tests.identity_support import (
    _persona_command,
    _profile_create_command,
    _revoke_profile_command,
)


def _adult_traits() -> PersonaTraits:
    return PersonaTraits(
        context="household_practical",
        tone="practical",
        depth="standard",
        learning_level="none",
    )


def _child_traits(profile_class: ProfileClass) -> PersonaTraits:
    return PersonaTraits(
        context="early_learning",
        tone="warm",
        depth="brief",
        learning_level=profile_class.value,
    )


@pytest.mark.asyncio
async def test_profile_passkey_source_must_be_passkey_before_binding_use(
    bound_profile_command_factory,
    passkey_auth_factory,
) -> None:
    command = bound_profile_command_factory(operation="create")
    auth = passkey_auth_factory(command.action_binding).model_copy(
        update={
            "assurance": AssuranceLevel.PIN_VERIFIED,
            "assurance_source": "pin",
        }
    )

    with pytest.raises(PermissionError, match="passkey_binding_required"):
        require_fresh_passkey(
            auth,
            command.action_binding,
            auth.consumed_at,
            binding_verifier=object(),
        )


@pytest.mark.asyncio
async def test_profile_create_fails_closed_on_household_binding_drift(
    identity_env,
    profile_service,
    owner,
) -> None:
    command = _profile_create_command(identity_env, profile_class=ProfileClass.ADULT)
    command = command.model_copy(
        update={
            "action_binding": command.action_binding.model_copy(update={"household_id": uuid4()})
        }
    )
    auth = identity_env.auth_context(owner.id, command.action_binding)

    with pytest.raises(PermissionError, match="profile_create_household_mismatch"):
        await profile_service.create(command, auth)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("profile_class", "guardian_marker", "expected_error"),
    [
        (ProfileClass.OWNER, None, "ordinary_profile_create_owner_forbidden"),
        (ProfileClass.ADULT, "owner", "adult_profile_guardian_forbidden"),
    ],
)
async def test_profile_create_rejects_owner_class_and_adult_guardian_lineage(
    identity_env,
    profile_service,
    owner,
    profile_class,
    guardian_marker,
    expected_error,
) -> None:
    command = _profile_create_command(
        identity_env,
        profile_class=profile_class,
        guardian_id=owner.id if guardian_marker == "owner" else None,
    )
    auth = identity_env.auth_context(owner.id, command.action_binding)

    async with identity_env.scope.open():
        with pytest.raises(PermissionError, match=expected_error):
            await profile_service.create(command, auth)


@pytest.mark.asyncio
async def test_profile_create_requires_actor_even_for_malformed_passkey_context(
    identity_env,
    profile_service,
    owner,
) -> None:
    command = _profile_create_command(identity_env, profile_class=ProfileClass.ADULT)
    auth = identity_env.auth_context(owner.id, command.action_binding)
    binding = command.action_binding.model_copy(update={"subject_id": None})
    command = command.model_copy(update={"action_binding": binding})
    auth = auth.model_copy(update={"binding": binding, "subject_id": None})

    async with identity_env.scope.open():
        with pytest.raises(PermissionError, match="current_owner_authority_required"):
            await profile_service.create(command, auth)


@pytest.mark.asyncio
async def test_current_policy_class_preserves_guest_and_active_subjects(
    profile_service,
    mutation_scope,
    adult_a,
) -> None:
    async with mutation_scope.open() as uow:
        assert (
            await profile_service.current_policy_class_in_uow(
                uow,
                adult_a.household_id,
                None,
            )
            is ProfileClass.GUEST
        )
        assert (
            await profile_service.current_policy_class_in_uow(
                uow,
                adult_a.household_id,
                adult_a.id,
            )
            is ProfileClass.ADULT
        )
        await uow.rollback()


@pytest.mark.asyncio
async def test_profile_read_helpers_preserve_active_profile_and_reject_stale_rows(
    identity_env,
    profile_service,
    mutation_scope,
    adult_a,
    adult_b,
) -> None:
    projection = await profile_service.get_projection(adult_a.household_id, adult_a.id)
    assert projection.subject_id == adult_a.id
    assert projection.profile_class is ProfileClass.ADULT

    async with mutation_scope.open() as uow:
        assert (
            await profile_service.require_current_active_in_uow(
                uow,
                adult_a.household_id,
                adult_a.id,
            )
        ).id == adult_a.id
        identity_env.profiles[adult_b.id] = adult_b.model_copy(update={"active": False})
        with pytest.raises(PermissionError, match="current_active_subject_required"):
            await profile_service.require_current_active_in_uow(
                uow,
                adult_b.household_id,
                adult_b.id,
            )
        await uow.rollback()


@pytest.mark.asyncio
async def test_persona_projection_keeps_anonymous_subject_as_guest(
    profile_service,
    household_id,
    now,
) -> None:
    projection = await profile_service.get_persona_projection(household_id, None, now)

    assert projection.role == "guest"
    assert projection.learning_level == "none"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("drift", "expected_error"),
    [
        ("actor", "authenticated_actor_mismatch"),
        ("household", "profile_persona_household_mismatch"),
        ("target_class", "profile_persona_target_class_changed"),
    ],
)
async def test_persona_update_fails_closed_on_actor_household_or_class_drift(
    identity_env,
    profile_service,
    adult_a,
    adult_b,
    drift,
    expected_error,
) -> None:
    command = _persona_command(identity_env, adult_a, adult_a.id, _adult_traits())
    auth = identity_env.auth_context(adult_a.id, command.action_binding)
    if drift == "actor":
        auth = auth.model_copy(update={"subject_id": adult_b.id})
    elif drift == "household":
        command = command.model_copy(
            update={
                "action_binding": command.action_binding.model_copy(
                    update={"household_id": uuid4()}
                )
            }
        )
        auth = identity_env.auth_context(adult_a.id, command.action_binding)
    else:
        identity_env.profiles[adult_a.id] = adult_a.model_copy(
            update={"profile_class": ProfileClass.K2}
        )

    async with identity_env.scope.open():
        with pytest.raises(PermissionError, match=expected_error):
            await profile_service.update_persona_traits(command, auth)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("repo_error", "expected_exception", "expected_error"),
    [
        (RuntimeError("version conflict"), StaleProfileVersion, "stale_profile_version"),
        (RuntimeError("storage unavailable"), RuntimeError, "storage unavailable"),
    ],
)
async def test_persona_update_distinguishes_stale_versions_from_storage_failures(
    monkeypatch,
    identity_env,
    profile_service,
    adult_a,
    repo_error,
    expected_exception,
    expected_error,
) -> None:
    async def fail_update_persona_expected_version(*args, **kwargs):
        del args, kwargs
        raise repo_error

    monkeypatch.setattr(
        identity_env.profile_repo,
        "update_persona_expected_version",
        fail_update_persona_expected_version,
    )
    command = _persona_command(identity_env, adult_a, adult_a.id, _adult_traits())
    auth = identity_env.auth_context(adult_a.id, command.action_binding)

    async with identity_env.scope.open():
        with pytest.raises(expected_exception, match=expected_error):
            await profile_service.update_persona_traits(command, auth)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("drift", "expected_error"),
    [
        ("household", "profile_revoke_household_mismatch"),
        ("inactive", "current_active_subject_required"),
        ("owner", "current_owner_replacement_transaction_required"),
        ("actor", "profile_revoke_authority_required"),
    ],
)
async def test_profile_revoke_fails_closed_before_authority_cascade(
    identity_env,
    profile_service,
    adult_a,
    owner,
    drift,
    expected_error,
) -> None:
    target = owner if drift == "owner" else adult_a
    command = _revoke_profile_command(identity_env, target)
    auth = identity_env.auth_context(command.action_binding.subject_id, command.action_binding)
    if drift == "household":
        command = command.model_copy(
            update={
                "action_binding": command.action_binding.model_copy(
                    update={"household_id": uuid4()}
                )
            }
        )
        auth = identity_env.auth_context(target.id, command.action_binding)
    elif drift == "inactive":
        identity_env.profiles[target.id] = target.model_copy(update={"active": False})
    elif drift == "actor":
        binding = command.action_binding.model_copy(update={"subject_id": None})
        command = command.model_copy(update={"action_binding": binding})
        auth = auth.model_copy(update={"binding": binding, "subject_id": None})

    async with identity_env.scope.open():
        with pytest.raises(PermissionError, match=expected_error):
            await profile_service.revoke(command, auth)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("repo_error", "expected_exception", "expected_error"),
    [
        (RuntimeError("stale row version"), StaleProfileVersion, "stale_profile_version"),
        (RuntimeError("storage unavailable"), RuntimeError, "storage unavailable"),
    ],
)
async def test_profile_revoke_distinguishes_stale_versions_from_storage_failures(
    monkeypatch,
    identity_env,
    profile_service,
    adult_a,
    repo_error,
    expected_exception,
    expected_error,
) -> None:
    async def fail_revoke_and_advance(*args, **kwargs):
        del args, kwargs
        raise repo_error

    monkeypatch.setattr(
        identity_env.profile_repo,
        "revoke_and_advance_authority_generation_expected_version",
        fail_revoke_and_advance,
    )
    command = _revoke_profile_command(identity_env, adult_a)
    auth = identity_env.auth_context(adult_a.id, command.action_binding)

    async with identity_env.scope.open():
        with pytest.raises(expected_exception, match=expected_error):
            await profile_service.revoke(command, auth)


@pytest.mark.asyncio
async def test_profile_in_uow_entrypoints_reject_cross_scope_uow_before_writes(
    identity_env,
    profile_service,
    mutation_scope,
    adult_a,
) -> None:
    create_command = _profile_create_command(identity_env, profile_class=ProfileClass.ADULT)
    persona_command = _persona_command(identity_env, adult_a, adult_a.id, _adult_traits())
    revoke_command = _revoke_profile_command(identity_env, adult_a)

    async with mutation_scope.open() as active_uow:
        async with identity_env.uow_factory() as other_uow:
            assert active_uow is not other_uow
            with pytest.raises(RuntimeError, match="profile_uow_scope_mismatch"):
                await profile_service.create_in_uow(
                    other_uow,
                    create_command,
                    identity_env.auth_context(
                        create_command.action_binding.subject_id,
                        create_command.action_binding,
                    ),
                )
            with pytest.raises(RuntimeError, match="profile_uow_scope_mismatch"):
                await profile_service.update_persona_traits_in_uow(
                    other_uow,
                    persona_command,
                    identity_env.auth_context(adult_a.id, persona_command.action_binding),
                )
            with pytest.raises(RuntimeError, match="profile_uow_scope_mismatch"):
                await profile_service.revoke_in_uow(
                    other_uow,
                    revoke_command,
                    identity_env.auth_context(adult_a.id, revoke_command.action_binding),
                )
            await other_uow.rollback()
        await active_uow.rollback()


@pytest.mark.asyncio
async def test_profile_in_uow_entrypoints_use_current_scope_for_successful_mutations(
    identity_env,
    profile_service,
    adult_a,
    adult_b,
) -> None:
    create_command = _profile_create_command(identity_env, profile_class=ProfileClass.ADULT)
    async with identity_env.scope.open() as uow:
        created = await profile_service.create_in_uow(
            uow,
            create_command,
            identity_env.auth_context(
                create_command.action_binding.subject_id,
                create_command.action_binding,
            ),
        )
        await uow.rollback()

    persona_command = _persona_command(identity_env, adult_a, adult_a.id, _adult_traits())
    async with identity_env.scope.open() as uow:
        updated = await profile_service.update_persona_traits_in_uow(
            uow,
            persona_command,
            identity_env.auth_context(adult_a.id, persona_command.action_binding),
        )
        await uow.rollback()

    revoke_command = _revoke_profile_command(identity_env, adult_b)
    async with identity_env.scope.open() as uow:
        revoked = await profile_service.revoke_in_uow(
            uow,
            revoke_command,
            identity_env.auth_context(adult_b.id, revoke_command.action_binding),
        )
        await uow.rollback()

    assert created.guardian_generation == 0
    assert updated.version == adult_a.version + 1
    assert revoked.authority_generation == adult_b.authority_generation + 1


def test_profile_persona_guards_reject_invalid_persisted_role_shapes(adult_a) -> None:
    guest_profile = adult_a.model_copy(update={"profile_class": ProfileClass.GUEST})
    command = _persona_command(type("Store", (), {})(), adult_a, adult_a.id, None)

    with pytest.raises(PermissionError, match="profile_persona_subject_authority_required"):
        ProfileService._require_persona_authority(guest_profile, command)

    with pytest.raises(PermissionError, match="adult_persona_learning_level_invalid"):
        ProfileService._require_valid_traits(
            ProfileClass.ADULT,
            PersonaTraits(
                context="general",
                tone="neutral",
                depth="standard",
                learning_level="k2",
            ),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case", "expected_error"),
    [
        ("adult_guardian_lookup_denied", "profile_revoke_authority_required"),
        ("child_malformed_null_guardian", "profile_revoke_authority_required"),
        ("child_guardian_lookup_denied", "profile_revoke_authority_required"),
        ("child_generation_changed", "profile_revoke_authority_required"),
        ("unsupported_persisted_class", "profile_revoke_authority_required"),
    ],
)
async def test_profile_revoke_authority_fails_closed_on_stale_or_malformed_lineage(
    identity_env,
    adult_a,
    adult_b,
    owner,
    case,
    expected_error,
) -> None:
    actor_id = adult_b.id
    profile = adult_a
    if case == "child_malformed_null_guardian":
        actor_id = None
        child = identity_env.profile_factory(
            ProfileClass.K2,
            name="child-null-guardian",
            guardian_id=owner.id,
        )
        profile = child.model_copy(update={"guardian_id": None})
    elif case == "child_guardian_lookup_denied":
        actor_id = adult_a.id
        profile = identity_env.profile_factory(
            ProfileClass.K2,
            name="child-non-owner-guardian",
            guardian_id=adult_a.id,
        )
    elif case == "child_generation_changed":
        actor_id = owner.id
        child = identity_env.profile_factory(
            ProfileClass.N1,
            name="child-generation-drift",
            guardian_id=owner.id,
        )
        profile = child.model_copy(update={"guardian_generation": 2})
    elif case == "unsupported_persisted_class":
        actor_id = adult_a.id
        profile = adult_a.model_copy(update={"profile_class": ProfileClass.GUEST})

    async with identity_env.uow_factory() as uow:
        with pytest.raises(PermissionError, match=expected_error):
            await ProfileService._require_revoke_authority(
                uow,
                profile,
                actor_id,
                identity_env.clock.now(),
            )
        await uow.rollback()


@pytest.mark.asyncio
async def test_profile_revoke_authority_allows_current_owner_or_current_child_guardian(
    identity_env,
    adult_a,
    owner,
) -> None:
    child = identity_env.profile_factory(
        ProfileClass.K2,
        name="current-owner-child-guardian",
        guardian_id=owner.id,
    )

    async with identity_env.uow_factory() as uow:
        await ProfileService._require_revoke_authority(
            uow,
            adult_a,
            owner.id,
            identity_env.clock.now(),
        )
        await ProfileService._require_revoke_authority(
            uow,
            child,
            owner.id,
            identity_env.clock.now(),
        )
        await uow.rollback()


@pytest.mark.asyncio
async def test_profile_revoke_authority_rejects_child_non_guardian_actor(
    identity_env,
    adult_a,
    owner,
) -> None:
    child = identity_env.profile_factory(
        ProfileClass.N1,
        name="child-non-guardian-revoke",
        guardian_id=owner.id,
    )

    async with identity_env.uow_factory() as uow:
        with pytest.raises(PermissionError, match="profile_revoke_authority_required"):
            await ProfileService._require_revoke_authority(
                uow,
                child,
                adult_a.id,
                identity_env.clock.now(),
            )
        await uow.rollback()


@pytest.mark.asyncio
async def test_profile_create_guardian_generation_rejects_unsupported_profile_class(
    identity_env,
    owner,
) -> None:
    command = _profile_create_command(identity_env, profile_class=ProfileClass.GUEST)

    async with identity_env.uow_factory() as uow:
        with pytest.raises(PermissionError, match="ordinary_profile_create_owner_forbidden"):
            await ProfileService._guardian_generation_for_create(
                uow,
                command,
                owner.id,
                identity_env.clock.now(),
            )
        await uow.rollback()
