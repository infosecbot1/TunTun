from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import unicodedata
import zlib
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
import tuntun_edge.diagnostics.capability as capability_module
from jsonschema import Draft202012Validator, FormatChecker
from pydantic import ValidationError
from tuntun_contracts.poc.framing import PttInputMode
from tuntun_contracts.speech import AudioFormat
from tuntun_edge.diagnostics.capability import (
    CapabilityDecision,
    CapabilityFact,
    CapabilityOutcome,
    CapabilityStatus,
    CheckStatus,
    HostObservation,
    LimitationCode,
    MediaObservation,
    ReachyCapabilityReportV1,
    RejectionReason,
    RuntimeDependency,
    RuntimeObservation,
    SafetyObservation,
    UnobservedReason,
    decide_capability,
    render_capability_schema,
)

CAPABILITY_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3] / "docs/evidence/reachy-a05-capability.schema.json"
)
SDK_ARTIFACT = b"trusted-sdk-wheel-bytes"
DAEMON_ARTIFACT = b"trusted-daemon-artifact-bytes"
DEPENDENCY_ARTIFACT = b"trusted-dependency-wheel-bytes"
REVERSIBLE_PRIVATE_BYTES = (b"\x00\x00>" * 10)[:-1]
COMPRESSIBLE_PRIVATE_BYTES = b"\x01" * 36


def dependency_inventory(count: int) -> tuple[RuntimeDependency, ...]:
    return tuple(
        RuntimeDependency(
            distribution=f"dep-{index:03d}",
            version=f"1.0.{index}",
            artifact_sha256=hashlib.sha256(DEPENDENCY_ARTIFACT).hexdigest(),
        )
        for index in range(count)
    )


def valid_report(**updates: object) -> ReachyCapabilityReportV1:
    passed = CheckStatus.PASSED
    available = CapabilityStatus.AVAILABLE
    dependency = RuntimeDependency(
        distribution="synthetic-media",
        version="7.8.9",
        artifact_sha256=hashlib.sha256(DEPENDENCY_ARTIFACT).hexdigest(),
    )
    runtime: dict[str, object] = {
        "daemon_evidence": {"observation": "observed"},
        "sdk_evidence": {"observation": "observed"},
        "interpreter_evidence": {"observation": "observed"},
        "sdk_version": "1.2.3",
        "daemon_version": "4.5.6",
        "python_version": "3.12.8",
        "python_abi": "cp312",
        "sdk_artifact_sha256": hashlib.sha256(SDK_ARTIFACT).hexdigest(),
        "daemon_artifact_sha256": hashlib.sha256(DAEMON_ARTIFACT).hexdigest(),
        "runtime_inventory_sha256": capability_module._runtime_inventory_sha256((dependency,)),
        "dependencies": (dependency,),
        "daemon_available": passed,
        "sdk_daemon_match": passed,
        "interpreter_supported": passed,
    }
    media: dict[str, object] = {
        "native_input_evidence": {"observation": "observed"},
        "native_output_evidence": {"observation": "observed"},
        "native_input_format": AudioFormat(
            sample_format="s16le",
            sample_rate_hz=48_000,
            channels=2,
            interleaved=True,
            channel_layout="reachy_native",
        ),
        "native_output_format": AudioFormat(
            sample_format="s16le",
            sample_rate_hz=48_000,
            channels=2,
            interleaved=True,
            channel_layout="reachy_native",
        ),
        "microphone_capture": passed,
        "speaker_playback": passed,
        "camera_frame_observed": passed,
        "playback_stop": passed,
        "aec": available,
        "doa": available,
    }
    safety: dict[str, object] = {
        "movement_enumerated": passed,
        "motion_stop": passed,
        "app_lock": passed,
        "controller_detection": passed,
        "controller_collision_clear": passed,
        "local_capture_input": available,
        "local_stop_input": available,
    }
    host: dict[str, object] = {
        "resource_evidence": {"observation": "observed"},
        "network_topology": passed,
        "bind_surface": passed,
        "ssh_boundary": passed,
        "resource_limits": passed,
        "report_privacy": passed,
        "rtc": available,
        "logical_cpu_count": 4,
        "memory_bytes": 2_147_483_648,
        "temperature_millicelsius": 45_000,
    }
    groups = (runtime, media, safety, host)
    values: dict[str, object] = {
        "schema_version": "tuntun.reachy-a05-capability.v1",
        "observed_at": datetime(2026, 8, 31, 8, 0, tzinfo=UTC),
    }
    for field, value in updates.items():
        matching = [group for group in groups if field in group]
        if matching:
            matching[0][field] = value
        else:
            values[field] = value
    values.update(
        runtime=RuntimeObservation.model_validate(runtime),
        media=MediaObservation.model_validate(media),
        safety=SafetyObservation.model_validate(safety),
        host=HostObservation.model_validate(host),
    )
    return ReachyCapabilityReportV1.model_validate(values)


def test_report_serializes_as_four_closed_bounded_observation_objects() -> None:
    encoded = valid_report().model_dump(mode="json")

    assert set(encoded) == {
        "schema_version",
        "observed_at",
        "runtime",
        "media",
        "safety",
        "host",
    }
    assert set(encoded["runtime"]) == set(RuntimeObservation.model_fields)
    assert set(encoded["media"]) == set(MediaObservation.model_fields)
    assert set(encoded["safety"]) == set(SafetyObservation.model_fields)
    assert set(encoded["host"]) == set(HostObservation.model_fields)


def test_capability_schema_render_is_deterministic_and_closed() -> None:
    first = render_capability_schema()
    second = render_capability_schema()

    assert first == second
    assert first.endswith(b"\n")
    schema = json.loads(first)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == (
        "https://tuntun.local/schemas/evidence/reachy-a05-capability.schema.json"
    )
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {
        "schema_version",
        "observed_at",
        "runtime",
        "media",
        "safety",
        "host",
    }
    for model_name in (
        "AudioFormat",
        "RuntimeDependency",
        "RuntimeObservation",
        "MediaObservation",
        "SafetyObservation",
        "HostObservation",
    ):
        assert schema["$defs"][model_name]["additionalProperties"] is False


def test_checked_schema_matches_renderer_and_report_round_trips() -> None:
    rendered = render_capability_schema()

    assert CAPABILITY_SCHEMA_PATH.read_bytes() == rendered
    schema = json.loads(rendered)
    Draft202012Validator.check_schema(schema)
    report = valid_report()
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(
        report.model_dump(mode="json")
    )
    assert ReachyCapabilityReportV1.model_validate_json(report.model_dump_json()) == report


@pytest.mark.parametrize(
    "distribution",
    (
        "synthetic_media",
        "synthetic.media",
    ),
)
def test_runtime_dependency_requires_pep503_normalized_distribution(
    distribution: str,
) -> None:
    with pytest.raises(ValidationError):
        RuntimeDependency(
            distribution=distribution,
            version="1.2.3",
            artifact_sha256="4" * 64,
        )


def test_runtime_dependencies_require_unique_canonical_tuple_order() -> None:
    alpha = RuntimeDependency(
        distribution="alpha-runtime",
        version="1.0.0",
        artifact_sha256="a" * 64,
    )
    zeta = RuntimeDependency(
        distribution="zeta-runtime",
        version="2.0.0",
        artifact_sha256="b" * 64,
    )

    assert valid_report(dependencies=(alpha, zeta)).runtime.dependencies == (alpha, zeta)
    with pytest.raises(ValidationError):
        valid_report(dependencies=(zeta, alpha))
    with pytest.raises(ValidationError):
        valid_report(dependencies=(alpha, alpha))


def test_observed_runtime_inventory_may_truthfully_be_empty() -> None:
    report = valid_report(dependencies=())

    assert report.runtime.dependencies == ()
    ReachyCapabilityReportV1.model_validate_json(report.model_dump_json())


@pytest.mark.parametrize(
    ("evidence_field", "value_field"),
    (
        ("daemon_evidence", "daemon_version"),
        ("sdk_evidence", "sdk_version"),
        ("interpreter_evidence", "python_version"),
        ("native_input_evidence", "native_input_format"),
        ("native_output_evidence", "native_output_format"),
        ("resource_evidence", "memory_bytes"),
    ),
)
def test_observed_and_unobserved_evidence_shapes_cannot_contradict_values(
    evidence_field: str,
    value_field: str,
) -> None:
    with pytest.raises(ValidationError):
        valid_report(
            **{
                evidence_field: {
                    "observation": "unobserved",
                    "reason": UnobservedReason.PROBE_ERROR,
                }
            }
        )
    with pytest.raises(ValidationError):
        valid_report(
            **{
                evidence_field: {"observation": "observed"},
                value_field: None,
            }
        )


@pytest.mark.parametrize(
    ("python_version", "python_abi"),
    (
        ("9.9.0", "cp999"),
        ("3.11.9", "cp312"),
        ("3.12.8", "cp311"),
    ),
)
def test_passed_interpreter_check_requires_an_exact_supported_pair(
    python_version: str,
    python_abi: str,
) -> None:
    with pytest.raises(ValidationError):
        valid_report(
            python_version=python_version,
            python_abi=python_abi,
            interpreter_supported=CheckStatus.PASSED,
        )

    schema = json.loads(render_capability_schema())
    encoded = valid_report().model_dump(mode="json")
    encoded["runtime"]["python_version"] = python_version
    encoded["runtime"]["python_abi"] = python_abi
    assert list(Draft202012Validator(schema).iter_errors(encoded))


def test_disconnected_daemon_report_omits_unobserved_runtime_evidence() -> None:
    report = valid_report(
        daemon_evidence={
            "observation": "unobserved",
            "reason": UnobservedReason.DEPENDENCY_UNAVAILABLE,
        },
        sdk_evidence={
            "observation": "unobserved",
            "reason": UnobservedReason.DEPENDENCY_UNAVAILABLE,
        },
        interpreter_evidence={
            "observation": "unobserved",
            "reason": UnobservedReason.NOT_ATTEMPTED,
        },
        sdk_version=None,
        daemon_version=None,
        python_version=None,
        python_abi=None,
        sdk_artifact_sha256=None,
        daemon_artifact_sha256=None,
        runtime_inventory_sha256=None,
        dependencies=None,
        daemon_available=CheckStatus.FAILED,
        sdk_daemon_match=CheckStatus.UNKNOWN,
        interpreter_supported=CheckStatus.UNKNOWN,
    )

    assert report.runtime.sdk_version is None
    assert report.runtime.daemon_version is None
    assert report.runtime.python_version is None
    assert report.runtime.dependencies is None
    assert report.runtime.daemon_evidence.reason.value == "dependency_unavailable"
    assert decide_with_privacy(report).rejection_reasons == (
        RejectionReason.DAEMON_UNAVAILABLE,
        RejectionReason.SDK_DAEMON_MISMATCH,
        RejectionReason.UNSUPPORTED_INTERPRETER,
    )


def test_failed_media_and_resource_reports_need_no_fabricated_measurements() -> None:
    report = valid_report(
        native_input_evidence={
            "observation": "unobserved",
            "reason": UnobservedReason.PROBE_ERROR,
        },
        native_output_evidence={
            "observation": "unobserved",
            "reason": UnobservedReason.PROBE_ERROR,
        },
        resource_evidence={
            "observation": "unobserved",
            "reason": UnobservedReason.PROBE_ERROR,
        },
        native_input_format=None,
        native_output_format=None,
        microphone_capture=CheckStatus.FAILED,
        speaker_playback=CheckStatus.FAILED,
        playback_stop=CheckStatus.FAILED,
        aec=CapabilityStatus.UNKNOWN,
        doa=CapabilityStatus.UNKNOWN,
        resource_limits=CheckStatus.FAILED,
        logical_cpu_count=None,
        memory_bytes=None,
        temperature_millicelsius=None,
    )

    assert report.media.native_input_format is None
    assert report.media.native_output_format is None
    assert report.host.logical_cpu_count is None
    assert report.host.memory_bytes is None
    assert report.host.temperature_millicelsius is None
    assert report.media.native_input_evidence.reason.value == "probe_error"
    assert report.host.resource_evidence.reason.value == "probe_error"


def test_failed_interpreter_check_may_carry_exact_unsupported_observation() -> None:
    report = valid_report(
        python_version="3.10.14",
        python_abi="cp310",
        interpreter_supported=CheckStatus.FAILED,
    )

    assert report.runtime.python_version == "3.10.14"
    assert report.runtime.python_abi == "cp310"
    assert decide_with_privacy(report).rejection_reasons == (
        RejectionReason.UNSUPPORTED_INTERPRETER,
    )


@pytest.mark.parametrize(
    "python_version",
    (
        "3.11",
        "3.11.8rc1",
        "3.11.8+local",
        "3.11.8.1",
        "03.11.8",
        "3.011.8",
        "3.11.08",
        "3.11.8\n",
    ),
)
def test_capability_rejects_noncanonical_interpreter_versions(
    python_version: str,
) -> None:
    with pytest.raises(ValidationError):
        valid_report(
            python_version=python_version,
            python_abi="cp311",
            interpreter_supported=CheckStatus.FAILED,
        )

    schema = json.loads(render_capability_schema())
    encoded = valid_report(
        python_version="3.10.14",
        python_abi="cp310",
        interpreter_supported=CheckStatus.FAILED,
    ).model_dump(mode="json")
    encoded["runtime"]["python_version"] = python_version
    assert list(Draft202012Validator(schema).iter_errors(encoded))


@pytest.mark.parametrize(
    "updates",
    (
        {"python_version": None, "python_abi": None},
        {"daemon_version": None, "daemon_artifact_sha256": None},
        {"sdk_version": None, "sdk_artifact_sha256": None},
        {"native_input_format": None},
        {"native_output_format": None},
        {
            "logical_cpu_count": None,
            "memory_bytes": None,
            "temperature_millicelsius": None,
        },
    ),
)
def test_passed_checks_reject_absent_required_evidence_in_model_and_schema(
    updates: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        valid_report(**updates)

    schema = json.loads(render_capability_schema())
    encoded = valid_report().model_dump(mode="json")
    for field, value in updates.items():
        for group in (encoded["runtime"], encoded["media"], encoded["host"]):
            if field in group:
                group[field] = value
                break
    assert list(Draft202012Validator(schema).iter_errors(encoded))


def test_capability_schema_marks_structural_runtime_validation_boundary() -> None:
    schema = json.loads(render_capability_schema())

    assert schema["x-tuntun-validation-scope"] == "structural"
    assert schema["x-tuntun-runtime-semantic-validation-required"] is True
    assert "model parsing" in schema["description"]


@pytest.mark.parametrize(
    ("field_path", "value"),
    (
        (("runtime", "sdk_artifact_sha256"), "1" * 64 + "\n"),
        (("runtime", "sdk_artifact_sha256"), "1" * 63),
        (("runtime", "sdk_version"), "1.2.3\n"),
    ),
)
def test_capability_model_and_schema_reject_trailing_or_short_tokens(
    field_path: tuple[str, str],
    value: str,
) -> None:
    group, field = field_path
    with pytest.raises(ValidationError):
        valid_report(**{field: value})

    schema = json.loads(render_capability_schema())
    encoded = valid_report().model_dump(mode="json")
    encoded[group][field] = value
    assert list(Draft202012Validator(schema).iter_errors(encoded))


@pytest.mark.parametrize("line_break", ("\n", "\r", "\r\n"))
@pytest.mark.parametrize(
    "field_path",
    (
        ("runtime", "sdk_version"),
        ("runtime", "daemon_version"),
        ("runtime", "python_abi"),
        ("dependency", "version"),
        ("dependency", "distribution"),
    ),
)
def test_capability_lexical_fields_reject_crlf_in_model_and_schema(
    field_path: tuple[str, str],
    line_break: str,
) -> None:
    group, field = field_path
    schema = json.loads(render_capability_schema())
    encoded = valid_report().model_dump(mode="json")
    if group == "dependency":
        original = encoded["runtime"]["dependencies"][0][field]
        encoded["runtime"]["dependencies"][0][field] = original + line_break
        dependency_values = encoded["runtime"]["dependencies"][0]
        with pytest.raises(ValidationError):
            RuntimeDependency.model_validate(dependency_values)
    else:
        original = encoded[group][field]
        encoded[group][field] = original + line_break
        with pytest.raises(ValidationError):
            valid_report(**{field: original + line_break})

    assert list(Draft202012Validator(schema).iter_errors(encoded))


@pytest.mark.parametrize(
    "private_alabel",
    (
        "xn--fa-hia",
        "build-xn--fa-hia-release",
        "BUILD-XN--FA-HIA-RELEASE",
    ),
)
def test_every_version_token_rejects_alabel_marker_in_model_and_schema(
    private_alabel: str,
) -> None:
    schema = json.loads(render_capability_schema())
    for field in ("sdk_version", "daemon_version"):
        with pytest.raises(ValidationError):
            valid_report(**{field: private_alabel})
        encoded = valid_report().model_dump(mode="json")
        encoded["runtime"][field] = private_alabel
        assert list(Draft202012Validator(schema).iter_errors(encoded))

    dependency = valid_report().runtime.dependencies[0]
    assert dependency is not None
    with pytest.raises(ValidationError):
        RuntimeDependency(
            distribution="synthetic-media",
            version=private_alabel,
            artifact_sha256="4" * 64,
        )
    encoded = valid_report().model_dump(mode="json")
    encoded["runtime"]["dependencies"][0]["version"] = private_alabel
    assert list(Draft202012Validator(schema).iter_errors(encoded))


@pytest.mark.parametrize(
    "private_alabel",
    ("xn--fa-hia", "build-xn--fa-hia-release"),
)
def test_every_distribution_name_rejects_alabel_marker_in_model_and_schema(
    private_alabel: str,
) -> None:
    with pytest.raises(ValidationError):
        RuntimeDependency(
            distribution=private_alabel,
            version="1.2.3",
            artifact_sha256="4" * 64,
        )

    schema = json.loads(render_capability_schema())
    encoded = valid_report().model_dump(mode="json")
    encoded["runtime"]["dependencies"][0]["distribution"] = private_alabel
    assert list(Draft202012Validator(schema).iter_errors(encoded))


def test_dependency_schema_marks_exact_duplicate_items_as_non_unique() -> None:
    schema = json.loads(render_capability_schema())
    dependencies_schema = schema["$defs"]["RuntimeObservation"]["properties"]["dependencies"]
    array_schema = next(
        choice for choice in dependencies_schema["anyOf"] if choice.get("type") == "array"
    )
    assert array_schema["uniqueItems"] is True
    encoded = valid_report().model_dump(mode="json")
    encoded["runtime"]["dependencies"].append(encoded["runtime"]["dependencies"][0].copy())

    assert list(Draft202012Validator(schema).iter_errors(encoded))


@pytest.mark.parametrize(
    "public_token",
    (
        "pyserial",
        "serialized-build",
        "hostnamecheck",
        "principals",
    ),
)
def test_private_identifier_guard_uses_exact_token_boundaries(
    public_token: str,
) -> None:
    dependency = RuntimeDependency(
        distribution="pyserial",
        version=public_token,
        artifact_sha256="4" * 64,
    )
    report = valid_report(
        sdk_version=public_token,
        dependencies=(dependency,),
    )
    schema = json.loads(render_capability_schema())

    Draft202012Validator(schema).validate(report.model_dump(mode="json"))


@pytest.mark.parametrize(
    "private_identifier",
    (
        "serial-device",
        "build-hostname",
        "build.principal.release",
        "build+ssid!release",
        "owner-username-build",
    ),
)
def test_private_identifier_guard_rejects_delimited_private_components(
    private_identifier: str,
) -> None:
    with pytest.raises(ValidationError):
        valid_report(sdk_version=private_identifier)

    schema = json.loads(render_capability_schema())
    encoded = valid_report().model_dump(mode="json")
    encoded["runtime"]["sdk_version"] = private_identifier
    assert list(Draft202012Validator(schema).iter_errors(encoded))


@pytest.mark.parametrize(
    "dotted_quad",
    (
        "192.168.50.22",
        "192.168.050.022",
        "999.999.999.999",
    ),
)
def test_syntactic_dotted_quad_rejection_has_model_schema_and_probe_parity(
    dotted_quad: str,
) -> None:
    with pytest.raises(ValidationError):
        valid_report(sdk_version=dotted_quad)

    schema = json.loads(render_capability_schema())
    encoded = valid_report().model_dump(mode="json")
    encoded["runtime"]["sdk_version"] = dotted_quad
    assert list(Draft202012Validator(schema).iter_errors(encoded))

    mutated = valid_report()
    object.__setattr__(mutated.runtime, "sdk_version", dotted_quad)
    with pytest.raises((ValidationError, ValueError)):
        trusted_probe_service(mutated)


def test_report_privacy_is_a_separate_probe_provenance_hard_check() -> None:
    dependency = RuntimeDependency(
        distribution="family-camera-build",
        version="opaque-release",
        artifact_sha256="4" * 64,
    )
    report = valid_report(
        dependencies=(dependency,),
        report_privacy=CheckStatus.FAILED,
    )
    schema = json.loads(render_capability_schema())
    description = schema["$defs"]["HostObservation"]["properties"]["report_privacy"]["description"]

    assert "exact known private values" in description
    assert "provenance" in description
    assert "lexical guardrail" in description
    assert decide_capability(report).rejection_reasons == (RejectionReason.REPORT_PRIVACY_FAILED,)


def private_scan_evidence(**updates: object) -> object:
    evidence_type = capability_module.PrivacyScanEvidence
    values: dict[str, object] = {
        "provenance": "delivered_reachy_probe_v1",
        "hostnames": ("private-reachy-host",),
        "fqdns": ("private-reachy.example.invalid",),
        "ip_addresses": ("192.168.50.22",),
        "mac_addresses": ("02:00:00:00:00:01",),
        "principals": ("private-owner",),
        "home_paths": ("/home/private-owner",),
        "serials": ("private-serial-123",),
        "ssids": ("private-family-network",),
        "key_material": (b"private-key-material",),
        "fingerprints": ("SHA256:private-fingerprint",),
        "content_buffers": (b"\x00private-content\xff",),
    }
    values.update(updates)
    coverage_types = (
        capability_module.PrivacyEvidenceClass,
        capability_module.PrivacyAcquisitionSource,
        capability_module.PrivacyCollectionStatus,
        capability_module.PrivacyEvidenceCoverage,
    )
    evidence_class, source, status, coverage_type = coverage_types
    coverage_map = (
        (evidence_class.HOSTNAME, source.SOCKET_IDENTITY, "hostnames"),
        (evidence_class.FQDN, source.SOCKET_IDENTITY, "fqdns"),
        (evidence_class.IP_ADDRESS, source.NETWORK_INTERFACES, "ip_addresses"),
        (evidence_class.MAC_ADDRESS, source.NETWORK_INTERFACES, "mac_addresses"),
        (evidence_class.PRINCIPAL, source.LOGIN_ACCOUNT, "principals"),
        (evidence_class.HOME_PATH, source.LOGIN_ACCOUNT, "home_paths"),
        (evidence_class.SERIAL, source.DEVICE_METADATA, "serials"),
        (evidence_class.SSID, source.NETWORK_CONFIGURATION, "ssids"),
        (evidence_class.KEY_MATERIAL, source.COMMISSIONING_CREDENTIALS, "key_material"),
        (evidence_class.FINGERPRINT, source.COMMISSIONING_CREDENTIALS, "fingerprints"),
        (evidence_class.CONTENT_BUFFER, source.BOUNDED_PROBE_BUFFERS, "content_buffers"),
    )
    values["coverage"] = tuple(
        coverage_type(
            evidence_class=private_class,
            acquisition_source=acquisition_source,
            status=(status.COMPLETE_WITH_VALUES if values[value_field] else status.COMPLETE_EMPTY),
        )
        for private_class, acquisition_source, value_field in coverage_map
    )
    return evidence_type(**values)


def empty_private_scan_evidence(**updates: object) -> object:
    empty_values: dict[str, object] = {
        "hostnames": (),
        "fqdns": (),
        "ip_addresses": (),
        "mac_addresses": (),
        "principals": (),
        "home_paths": (),
        "serials": (),
        "ssids": (),
        "key_material": (),
        "fingerprints": (),
        "content_buffers": (),
    }
    empty_values.update(updates)
    return private_scan_evidence(**empty_values)


def trusted_probe_service(
    report: ReachyCapabilityReportV1,
    *,
    evidence: object | None = None,
) -> tuple[object, object]:
    runtime = report.runtime
    constructor = capability_module._COMPOSITION_ROOT_CONSTRUCTOR

    def version_observation(
        value: str,
        source: object,
    ) -> object:
        return capability_module.RuntimeVersionObservation(
            source=source,
            raw=value.encode("ascii") + b"\n",
            constructor=constructor,
        )

    sdk_artifact = (
        None
        if runtime.sdk_version is None
        else capability_module.RuntimeArtifactObservation(
            distribution="reachy-sdk",
            version=version_observation(
                runtime.sdk_version,
                capability_module.RuntimeVersionSource.PACKAGE_METADATA,
            ),
            artifact=SDK_ARTIFACT,
            constructor=constructor,
        )
    )
    daemon_artifact = (
        None
        if runtime.daemon_version is None
        else capability_module.RuntimeArtifactObservation(
            distribution="reachy-daemon",
            version=version_observation(
                runtime.daemon_version,
                capability_module.RuntimeVersionSource.DAEMON_PROTOCOL,
            ),
            artifact=DAEMON_ARTIFACT,
            constructor=constructor,
        )
    )
    interpreter = (
        None
        if runtime.python_version is None or runtime.python_abi is None
        else capability_module.InterpreterVersionObservation(
            version=tuple(int(part) for part in runtime.python_version.split(".")),
            abi=runtime.python_abi,
            constructor=constructor,
        )
    )
    dependency_artifacts = (
        None
        if runtime.dependencies is None
        else tuple(
            capability_module.RuntimeArtifactObservation(
                distribution=dependency.distribution,
                version=version_observation(
                    dependency.version,
                    capability_module.RuntimeVersionSource.PACKAGE_METADATA,
                ),
                artifact=DEPENDENCY_ARTIFACT,
                constructor=constructor,
            )
            for dependency in runtime.dependencies
        )
    )
    runtime_builder = capability_module.RuntimeObservationBuilder(
        constructor=constructor,
        daemon_evidence=runtime.daemon_evidence,
        sdk_evidence=runtime.sdk_evidence,
        interpreter_evidence=runtime.interpreter_evidence,
        sdk_artifact=sdk_artifact,
        daemon_artifact=daemon_artifact,
        interpreter=interpreter,
        dependencies=dependency_artifacts,
        daemon_available=runtime.daemon_available,
        sdk_daemon_match=runtime.sdk_daemon_match,
        interpreter_supported=runtime.interpreter_supported,
    )
    producer = capability_module.TrustedCapabilityProducer(
        observed_at=report.observed_at,
        runtime=runtime_builder,
        media=capability_module.MediaObservationBuilder(report.media, constructor=constructor),
        safety=capability_module.SafetyObservationBuilder(report.safety, constructor=constructor),
        host=capability_module.HostObservationBuilder(report.host, constructor=constructor),
        privacy=capability_module.PrivacyEvidenceBuilder(
            private_scan_evidence() if evidence is None else evidence,
            constructor=constructor,
        ),
        constructor=constructor,
    )
    return (
        capability_module.CapabilityProbeService(producer, constructor=constructor),
        producer,
    )


def runtime_artifact_observation(
    distribution: str,
    artifact: bytes,
    *,
    source: object = capability_module.RuntimeVersionSource.PACKAGE_METADATA,
) -> object:
    constructor = capability_module._COMPOSITION_ROOT_CONSTRUCTOR
    return capability_module.RuntimeArtifactObservation(
        distribution=distribution,
        version=capability_module.RuntimeVersionObservation(
            source=source,
            raw=b"1.2.3\n",
            constructor=constructor,
        ),
        artifact=artifact,
        constructor=constructor,
    )


def build_runtime_observation(
    *,
    sdk_artifact: object,
    daemon_artifact: object,
    dependencies: tuple[object, ...],
) -> object:
    observed = capability_module.ObservedEvidence(observation="observed")
    unobserved = capability_module.UnobservedEvidence(
        observation="unobserved",
        reason=UnobservedReason.NOT_ATTEMPTED,
    )
    return capability_module.RuntimeObservationBuilder(
        constructor=capability_module._COMPOSITION_ROOT_CONSTRUCTOR,
        daemon_evidence=observed,
        sdk_evidence=observed,
        interpreter_evidence=unobserved,
        sdk_artifact=sdk_artifact,
        daemon_artifact=daemon_artifact,
        interpreter=None,
        dependencies=dependencies,
        daemon_available=CheckStatus.PASSED,
        sdk_daemon_match=CheckStatus.PASSED,
        interpreter_supported=CheckStatus.UNKNOWN,
    )


def decide_with_privacy(report: ReachyCapabilityReportV1) -> CapabilityDecision:
    probe_service, _ = trusted_probe_service(report)
    return decide_capability(probe_service.probe())


_STANDARD_B64 = base64.b64encode(REVERSIBLE_PRIVATE_BYTES).decode("ascii")
_URLSAFE_B64 = base64.urlsafe_b64encode(REVERSIBLE_PRIVATE_BYTES).decode("ascii")
_BASE32 = base64.b32encode(REVERSIBLE_PRIVATE_BYTES).decode("ascii")
REVERSIBLE_PRIVATE_ENCODINGS = (
    pytest.param(REVERSIBLE_PRIVATE_BYTES, REVERSIBLE_PRIVATE_BYTES.hex(), id="hex-lower"),
    pytest.param(REVERSIBLE_PRIVATE_BYTES, REVERSIBLE_PRIVATE_BYTES.hex().upper(), id="hex-upper"),
    pytest.param(REVERSIBLE_PRIVATE_BYTES, _STANDARD_B64, id="base64-padded"),
    pytest.param(REVERSIBLE_PRIVATE_BYTES, _STANDARD_B64.rstrip("="), id="base64-unpadded"),
    pytest.param(REVERSIBLE_PRIVATE_BYTES, _URLSAFE_B64, id="base64url-padded"),
    pytest.param(REVERSIBLE_PRIVATE_BYTES, _URLSAFE_B64.rstrip("="), id="base64url-unpadded"),
    pytest.param(REVERSIBLE_PRIVATE_BYTES, _BASE32, id="base32-padded-upper"),
    pytest.param(REVERSIBLE_PRIVATE_BYTES, _BASE32.rstrip("="), id="base32-unpadded-upper"),
    pytest.param(REVERSIBLE_PRIVATE_BYTES, _BASE32.lower(), id="base32-padded-lower"),
    pytest.param(
        REVERSIBLE_PRIVATE_BYTES,
        _BASE32.rstrip("=").lower(),
        id="base32-unpadded-lower",
    ),
)


@pytest.mark.parametrize("evidence_field", ("key_material", "content_buffers"))
@pytest.mark.parametrize(("private_bytes", "encoded"), REVERSIBLE_PRIVATE_ENCODINGS)
def test_trusted_snapshot_rejects_whole_reversible_binary_evidence_encodings(
    evidence_field: str,
    private_bytes: bytes,
    encoded: str,
) -> None:
    generated = capability_module._reversible_binary_representations(private_bytes)
    assert encoded in generated
    assert len(generated) <= capability_module._MAX_PRIVACY_BINARY_REPRESENTATIONS_PER_VALUE
    assert all(
        len(value.encode("ascii")) <= capability_module._MAX_PRIVACY_PUBLIC_TEXT_VALUE_BYTES
        for value in generated
    )
    if "=" in encoded:
        with pytest.raises(ValidationError):
            valid_report(sdk_version=encoded)
        return
    service, _ = trusted_probe_service(
        valid_report(sdk_version=encoded),
        evidence=empty_private_scan_evidence(**{evidence_field: (private_bytes,)}),
    )

    with pytest.raises(capability_module.PrivacyScanRejected):
        service.probe()


@pytest.mark.parametrize("evidence_field", ("key_material", "content_buffers"))
def test_reversible_encoding_scan_has_benign_and_one_way_hash_controls(
    evidence_field: str,
) -> None:
    evidence = empty_private_scan_evidence(**{evidence_field: (REVERSIBLE_PRIVATE_BYTES,)})
    for public_token in (
        "benign-public-release",
        hashlib.sha256(REVERSIBLE_PRIVATE_BYTES).hexdigest(),
        hmac.new(b"probe-key", REVERSIBLE_PRIVATE_BYTES, hashlib.sha256).hexdigest(),
    ):
        service, _ = trusted_probe_service(
            valid_report(sdk_version=public_token),
            evidence=evidence,
        )
        assert decide_capability(service.probe()).outcome is CapabilityOutcome.ACCEPTED


@pytest.mark.parametrize(
    ("evidence_field", "private_identifier", "packed"),
    (
        ("ip_addresses", "192.168.1.2", b"\xc0\xa8\x01\x02"),
        ("mac_addresses", "aa:bb:cc:dd:ee:ff", b"\xaa\xbb\xcc\xdd\xee\xff"),
    ),
)
def test_packed_network_identifier_encodings_are_private_representation_sources(
    evidence_field: str,
    private_identifier: str,
    packed: bytes,
) -> None:
    evidence = empty_private_scan_evidence(**{evidence_field: (private_identifier,)})
    for encoded in {
        base64.b64encode(packed).rstrip(b"=").decode("ascii"),
        base64.urlsafe_b64encode(packed).rstrip(b"=").decode("ascii"),
    }:
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+!-]{0,63}", encoded) is None:
            continue
        service, _ = trusted_probe_service(
            valid_report(sdk_version=encoded),
            evidence=evidence,
        )
        with pytest.raises(capability_module.PrivacyScanRejected):
            service.probe()
    raw_service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(b"x-" + packed + b"-x")),
        evidence=evidence,
    )
    with pytest.raises(capability_module.PrivacyScanRejected):
        raw_service.probe()
    for padded in {base64.b64encode(packed), base64.urlsafe_b64encode(packed)}:
        service, _ = trusted_probe_service(
            valid_report(sdk_version=_zlib_base64url_token(padded)),
            evidence=evidence,
        )
        with pytest.raises(capability_module.PrivacyScanRejected):
            service.probe()

    benign_service, _ = trusted_probe_service(
        valid_report(sdk_version=base64.urlsafe_b64encode(b"public").rstrip(b"=").decode()),
        evidence=evidence,
    )
    assert decide_capability(benign_service.probe()).outcome is CapabilityOutcome.ACCEPTED


def test_ipv6_equivalent_text_inside_zlib_is_private() -> None:
    evidence = empty_private_scan_evidence(ip_addresses=("2001:db8::1",))
    equivalent = b"2001:0db8:0:0:0:0:0:1"
    service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(equivalent)),
        evidence=evidence,
    )

    with pytest.raises(capability_module.PrivacyScanRejected):
        service.probe()

    benign_service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(b"2001:0db8:0:0:0:0:0:2")),
        evidence=evidence,
    )
    assert decide_capability(benign_service.probe()).outcome is CapabilityOutcome.ACCEPTED


@pytest.mark.parametrize("render", (str, lambda value: f"0x{value:x}"))
def test_numeric_mac_representation_is_private(render: Callable[[int], str]) -> None:
    evidence = empty_private_scan_evidence(mac_addresses=("00:11:22:33:44:55",))
    mac_integer = int.from_bytes(bytes.fromhex("001122334455"), "big")
    rendered_mac = render(mac_integer)
    service, _ = trusted_probe_service(
        valid_report(sdk_version=rendered_mac),
        evidence=evidence,
    )

    with pytest.raises(capability_module.PrivacyScanRejected):
        service.probe()

    benign_service, _ = trusted_probe_service(
        valid_report(sdk_version=render(mac_integer + 1)),
        evidence=evidence,
    )
    assert decide_capability(benign_service.probe()).outcome is CapabilityOutcome.ACCEPTED


def test_base64_private_representation_matching_remains_case_sensitive() -> None:
    canonical = base64.b64encode(REVERSIBLE_PRIVATE_BYTES).rstrip(b"=")
    altered = canonical[:1].swapcase() + canonical[1:]
    assert base64.b64decode(canonical + b"=" * (-len(canonical) % 4)) == REVERSIBLE_PRIVATE_BYTES
    assert base64.b64decode(altered + b"=" * (-len(altered) % 4)) != REVERSIBLE_PRIVATE_BYTES
    evidence = empty_private_scan_evidence(content_buffers=(REVERSIBLE_PRIVATE_BYTES,))

    direct_service, _ = trusted_probe_service(
        valid_report(sdk_version=altered.decode("ascii")),
        evidence=evidence,
    )
    assert decide_capability(direct_service.probe()).outcome is CapabilityOutcome.ACCEPTED

    compressed_service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(altered)),
        evidence=evidence,
    )
    assert decide_capability(compressed_service.probe()).outcome is CapabilityOutcome.ACCEPTED


def test_non_ascii_binary_evidence_remains_byte_exact_and_does_not_break_text_scan() -> None:
    private_bytes = ("\N{CJK UNIFIED IDEOGRAPH-79D8}\N{CJK UNIFIED IDEOGRAPH-5BC6}" * 8).encode()
    evidence = empty_private_scan_evidence(content_buffers=(private_bytes,))
    benign_service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(b"public-value")),
        evidence=evidence,
    )
    assert decide_capability(benign_service.probe()).outcome is CapabilityOutcome.ACCEPTED

    private_service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(private_bytes)),
        evidence=evidence,
    )
    with pytest.raises(capability_module.PrivacyScanRejected):
        private_service.probe()


def test_privacy_scan_budget_accepts_exact_work_and_memory_limits_only() -> None:
    capability_module._require_privacy_scan_budget(
        report_value_count=capability_module._MAX_PRIVACY_REPORT_TEXT_VALUES,
        private_value_count=capability_module._MAX_PRIVACY_SCAN_PRIVATE_VALUES,
        transformed_value_bytes=capability_module._MAX_PRIVACY_TRANSFORMED_VALUE_BYTES,
    )
    with pytest.raises(capability_module.PrivacyScanUnavailable, match="work bound"):
        capability_module._require_privacy_scan_budget(
            report_value_count=capability_module._MAX_PRIVACY_REPORT_TEXT_VALUES,
            private_value_count=capability_module._MAX_PRIVACY_SCAN_PRIVATE_VALUES + 1,
            transformed_value_bytes=capability_module._MAX_PRIVACY_TRANSFORMED_VALUE_BYTES,
        )
    with pytest.raises(capability_module.PrivacyScanUnavailable, match="work bound"):
        capability_module._require_privacy_scan_budget(
            report_value_count=capability_module._MAX_PRIVACY_REPORT_TEXT_VALUES + 1,
            private_value_count=capability_module._MAX_PRIVACY_SCAN_PRIVATE_VALUES,
            transformed_value_bytes=capability_module._MAX_PRIVACY_TRANSFORMED_VALUE_BYTES,
        )
    with pytest.raises(capability_module.PrivacyScanUnavailable, match="memory bound"):
        capability_module._require_privacy_scan_budget(
            report_value_count=capability_module._MAX_PRIVACY_REPORT_TEXT_VALUES,
            private_value_count=capability_module._MAX_PRIVACY_SCAN_PRIVATE_VALUES,
            transformed_value_bytes=capability_module._MAX_PRIVACY_TRANSFORMED_VALUE_BYTES + 1,
        )


def _zlib_base64url_token(
    value: bytes,
    *,
    level: int = 6,
    strategy: int = zlib.Z_DEFAULT_STRATEGY,
) -> str:
    compressor = zlib.compressobj(
        level,
        zlib.DEFLATED,
        zlib.MAX_WBITS,
        8,
        strategy,
    )
    compressed = compressor.compress(value) + compressor.flush()
    return base64.urlsafe_b64encode(compressed).rstrip(b"=").decode("ascii")


ZLIB_ENCODINGS = tuple(
    pytest.param(
        _zlib_base64url_token(COMPRESSIBLE_PRIVATE_BYTES, level=level), id=f"level-{level}"
    )
    for level in range(10)
) + tuple(
    pytest.param(
        _zlib_base64url_token(COMPRESSIBLE_PRIVATE_BYTES, strategy=strategy),
        id=name,
    )
    for name, strategy in (
        ("strategy-default", zlib.Z_DEFAULT_STRATEGY),
        ("strategy-filtered", zlib.Z_FILTERED),
        ("strategy-huffman", zlib.Z_HUFFMAN_ONLY),
        ("strategy-rle", zlib.Z_RLE),
        ("strategy-fixed", zlib.Z_FIXED),
    )
)


@pytest.mark.parametrize("evidence_field", ("key_material", "content_buffers"))
@pytest.mark.parametrize("encoded", ZLIB_ENCODINGS)
def test_privacy_scan_decodes_canonical_zlib_base64url_independent_of_encoder(
    evidence_field: str,
    encoded: str,
) -> None:
    service, _ = trusted_probe_service(
        valid_report(sdk_version=encoded),
        evidence=empty_private_scan_evidence(**{evidence_field: (COMPRESSIBLE_PRIVATE_BYTES,)}),
    )

    with pytest.raises(capability_module.PrivacyScanRejected):
        service.probe()


def test_zlib_base64url_decoder_is_canonical_complete_and_bounded() -> None:
    value = b"x" * 1_024
    token = _zlib_base64url_token(value)

    assert (
        capability_module._decode_canonical_zlib_base64url(
            token,
            max_output_bytes=len(value),
        )
        == value
    )
    with pytest.raises(capability_module.PrivacyScanUnavailable, match="decompression bound"):
        capability_module._decode_canonical_zlib_base64url(
            _zlib_base64url_token(value + b"x"),
            max_output_bytes=len(value),
        )
    assert (
        capability_module._decode_canonical_zlib_base64url(
            base64.urlsafe_b64encode(b"not-zlib").rstrip(b"=").decode("ascii"),
            max_output_bytes=len(value),
        )
        is None
    )
    corrupt_stream = bytearray(zlib.compress(value))
    corrupt_stream[-1] ^= 0x01
    corrupt_token = base64.urlsafe_b64encode(corrupt_stream).rstrip(b"=").decode("ascii")
    for invalid_token in (
        corrupt_token,
        "eJzLL0rJzEssqtQtKMosSyxJ1c0sztBNKk1LSy0CAJdhCqg",
    ):
        assert (
            capability_module._decode_canonical_zlib_base64url(
                invalid_token,
                max_output_bytes=len(value),
            )
            is None
        )
        corrupt_service, _ = trusted_probe_service(
            valid_report(sdk_version=invalid_token),
            evidence=empty_private_scan_evidence(),
        )
        assert decide_capability(corrupt_service.probe()).outcome is CapabilityOutcome.ACCEPTED
    corrupt_private_service, _ = trusted_probe_service(
        valid_report(sdk_version=corrupt_token),
        evidence=empty_private_scan_evidence(content_buffers=(value,)),
    )
    with pytest.raises(capability_module.PrivacyScanRejected):
        corrupt_private_service.probe()
    contained_private = b"private-buffer!!"
    containing_payload = b"prefix-" + contained_private + b"-suffix"
    valid_containing_token = (
        base64.urlsafe_b64encode(zlib.compress(containing_payload)).rstrip(b"=").decode("ascii")
    )
    valid_containing_service, _ = trusted_probe_service(
        valid_report(sdk_version=valid_containing_token),
        evidence=empty_private_scan_evidence(content_buffers=(contained_private,)),
    )
    with pytest.raises(capability_module.PrivacyScanRejected):
        valid_containing_service.probe()

    containing_stream = bytearray(zlib.compress(containing_payload))
    containing_stream[-1] ^= 0x01
    containing_token = base64.urlsafe_b64encode(containing_stream).rstrip(b"=").decode("ascii")
    corrupt_containing_service, _ = trusted_probe_service(
        valid_report(sdk_version=containing_token),
        evidence=empty_private_scan_evidence(content_buffers=(contained_private,)),
    )
    with pytest.raises(capability_module.PrivacyScanRejected):
        corrupt_containing_service.probe()
    assert (
        capability_module._decode_canonical_zlib_base64url(
            token + "=",
            max_output_bytes=len(value),
        )
        is None
    )
    trailing = (
        base64.urlsafe_b64encode(zlib.compress(value) + b"trailing").rstrip(b"=").decode("ascii")
    )
    assert (
        capability_module._decode_canonical_zlib_base64url(
            trailing,
            max_output_bytes=len(value),
        )
        is None
    )


@pytest.mark.parametrize("trailer_bytes_removed", (1, 2, 3))
def test_zlib_truncated_trailer_still_scans_the_complete_recovered_payload(
    trailer_bytes_removed: int,
) -> None:
    private_value = b"x" * 1_024
    truncated_stream = zlib.compress(private_value)[:-trailer_bytes_removed]
    truncated_token = base64.urlsafe_b64encode(truncated_stream).rstrip(b"=").decode("ascii")
    assert (
        capability_module._decode_canonical_zlib_base64url(
            truncated_token,
            max_output_bytes=len(private_value),
        )
        is None
    )

    private_service, _ = trusted_probe_service(
        valid_report(sdk_version=truncated_token),
        evidence=empty_private_scan_evidence(content_buffers=(private_value,)),
    )
    with pytest.raises(capability_module.PrivacyScanRejected):
        private_service.probe()

    unrelated_service, _ = trusted_probe_service(
        valid_report(sdk_version=truncated_token),
        evidence=empty_private_scan_evidence(content_buffers=(b"y" * 1_024,)),
    )
    assert decide_capability(unrelated_service.probe()).outcome is CapabilityOutcome.ACCEPTED


@pytest.mark.parametrize(
    ("header_index", "header_mask"),
    (
        pytest.param(1, 0x01, id="fcheck"),
        pytest.param(0, 0x01, id="cm-method"),
        pytest.param(0, 0x10, id="cmf-cinfo"),
        pytest.param(1, 0x20, id="fdict"),
    ),
)
def test_zlib_corrupt_header_still_scans_the_complete_raw_deflate_payload(
    header_index: int,
    header_mask: int,
) -> None:
    private_value = b"x" * 1_024
    corrupt_stream = bytearray(zlib.compress(private_value))
    corrupt_stream[header_index] ^= header_mask
    corrupt_token = base64.urlsafe_b64encode(corrupt_stream).rstrip(b"=").decode("ascii")
    assert (
        capability_module._decode_canonical_zlib_base64url(
            corrupt_token,
            max_output_bytes=len(private_value),
        )
        is None
    )

    private_service, _ = trusted_probe_service(
        valid_report(sdk_version=corrupt_token),
        evidence=empty_private_scan_evidence(content_buffers=(private_value,)),
    )
    with pytest.raises(capability_module.PrivacyScanRejected):
        private_service.probe()

    unrelated_service, _ = trusted_probe_service(
        valid_report(sdk_version=corrupt_token),
        evidence=empty_private_scan_evidence(content_buffers=(b"y" * 1_024,)),
    )
    assert decide_capability(unrelated_service.probe()).outcome is CapabilityOutcome.ACCEPTED


def test_one_zlib_layer_rejects_nested_invalid_compression_method() -> None:
    private_value = b"x" * 1_024
    corrupt_stream = bytearray(zlib.compress(private_value))
    corrupt_stream[0] ^= 0x01
    service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(bytes(corrupt_stream))),
        evidence=empty_private_scan_evidence(content_buffers=(private_value,)),
    )

    with pytest.raises(capability_module.PrivacyScanUnavailable, match="nested compression"):
        service.probe()


def test_zlib_preset_dictionary_stream_fails_closed_without_the_dictionary() -> None:
    private_value = b"family-secret-123"
    preset_dictionary = b"common-prefix-family-secret-dictionary"
    compressor = zlib.compressobj(
        level=9,
        wbits=zlib.MAX_WBITS,
        zdict=preset_dictionary,
    )
    compressed = compressor.compress(private_value) + compressor.flush()
    token = base64.urlsafe_b64encode(compressed).rstrip(b"=").decode("ascii")
    assert token == "ePki7w8KQxU3NDIGADrgBfk"

    for framed in (compressed, b"X" + compressed):
        framed_token = base64.urlsafe_b64encode(framed).rstrip(b"=").decode("ascii")
        with pytest.raises(capability_module.PrivacyScanUnavailable, match="preset dictionary"):
            capability_module._decode_canonical_zlib_base64url_with_work(
                framed_token,
                max_output_bytes=capability_module._MAX_PRIVACY_DECOMPRESSED_TOKEN_BYTES,
            )

    for evidence in (
        empty_private_scan_evidence(content_buffers=(private_value,)),
        empty_private_scan_evidence(),
    ):
        service, _ = trusted_probe_service(
            valid_report(sdk_version=token),
            evidence=evidence,
        )
        with pytest.raises(capability_module.PrivacyScanUnavailable, match="preset dictionary"):
            service.probe()


@pytest.mark.parametrize("nested", (False, True))
def test_zlib_corrupt_fcheck_preset_dictionary_stream_fails_closed(nested: bool) -> None:
    preset_dictionary = b"common-prefix-family-secret-dictionary"
    compressor = zlib.compressobj(level=9, wbits=zlib.MAX_WBITS, zdict=preset_dictionary)
    compressed = bytearray(compressor.compress(b"family-secret-123") + compressor.flush())
    compressed[1] ^= 0x01
    payload = bytes(compressed)
    token = (
        _zlib_base64url_token(payload)
        if nested
        else base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    )
    service, _ = trusted_probe_service(
        valid_report(sdk_version=token),
        evidence=empty_private_scan_evidence(),
    )

    with pytest.raises(capability_module.PrivacyScanUnavailable, match="preset dictionary"):
        service.probe()


@pytest.mark.parametrize("nested", (False, True))
@pytest.mark.parametrize(
    ("header_index", "header_mask"),
    (
        pytest.param(0, 0x01, id="cm-method"),
        pytest.param(0, 0x10, id="cmf-cinfo"),
        pytest.param(1, 0x20, id="fdict-flag"),
    ),
)
def test_zlib_single_bit_corrupt_preset_dictionary_header_fails_closed(
    nested: bool,
    header_index: int,
    header_mask: int,
) -> None:
    compressor = zlib.compressobj(
        level=9,
        wbits=zlib.MAX_WBITS,
        zdict=b"common-prefix-family-secret-dictionary",
    )
    compressed = bytearray(compressor.compress(b"family-secret-123") + compressor.flush())
    compressed[header_index] ^= header_mask
    payload = bytes(compressed)
    token = (
        _zlib_base64url_token(payload)
        if nested
        else base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    )
    service, _ = trusted_probe_service(
        valid_report(sdk_version=token),
        evidence=empty_private_scan_evidence(),
    )

    with pytest.raises(capability_module.PrivacyScanUnavailable, match="preset dictionary"):
        service.probe()


def test_malformed_fdict_partial_output_is_charged_to_the_exact_work_bound() -> None:
    compressor = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    corrupt_raw = bytearray(compressor.compress(b"a" * 10_000) + compressor.flush())
    corrupt_raw[0] ^= 0x01
    framed = b"\x78\xf9" + b"\x00\x00\x00\x01" + bytes(corrupt_raw) + b"ABCD"
    token = base64.urlsafe_b64encode(framed).rstrip(b"=").decode("ascii")
    assert len(token) <= capability_module._MAX_PRIVACY_PUBLIC_TEXT_VALUE_BYTES

    assert capability_module._inspect_preset_dictionary_frame(
        framed,
        max_output_bytes=10_000,
    ) == (True, 10_000)
    with pytest.raises(capability_module.PrivacyScanUnavailable, match="preset dictionary"):
        capability_module._decode_canonical_zlib_base64url_with_work(
            token,
            max_output_bytes=10_000,
        )

    with pytest.raises(capability_module.PrivacyScanUnavailable, match="decompression bound"):
        capability_module._decode_canonical_zlib_base64url_with_work(
            token,
            max_output_bytes=9_999,
        )


@pytest.mark.parametrize("fcheck_mask", (0, 0x01), ids=("exact", "fcheck-bit-flip"))
def test_fdict_polyglot_cannot_hide_behind_a_complete_empty_raw_stream(
    fcheck_mask: int,
) -> None:
    private = b"private-buffer!!"
    dictionary = bytearray([0xFF] * 257)
    dictionary[166] -= 1
    dictionary[171] -= 14
    assert zlib.adler32(dictionary) == 0x03000000
    remainder = private[1:]
    raw_body = (
        b"\x00\x01\x00\xfe\xff"
        + private[:1]
        + b"\x01"
        + len(remainder).to_bytes(2, "little")
        + (0xFFFF - len(remainder)).to_bytes(2, "little")
        + remainder
    )
    frame = bytearray(
        b"\x78\xf9"
        + zlib.adler32(dictionary).to_bytes(4, "big")
        + raw_body
        + zlib.adler32(private).to_bytes(4, "big")
    )
    decompressor = zlib.decompressobj(zlib.MAX_WBITS, zdict=bytes(dictionary))
    assert decompressor.decompress(frame) + decompressor.flush() == private
    assert decompressor.eof
    frame[1] ^= fcheck_mask
    candidate = bytes(frame)
    token = base64.urlsafe_b64encode(candidate).rstrip(b"=").decode("ascii")
    assert len(token) == 48
    assert len(token) <= capability_module._MAX_PRIVACY_PUBLIC_TEXT_VALUE_BYTES
    assert capability_module._inspect_preset_dictionary_frame(
        candidate,
        max_output_bytes=capability_module._MAX_PRIVACY_DECOMPRESSED_TOKEN_BYTES,
    ) == (True, len(private))

    with pytest.raises(capability_module.PrivacyScanUnavailable, match="preset dictionary"):
        capability_module._decode_canonical_zlib_base64url_with_work(
            token,
            max_output_bytes=capability_module._MAX_PRIVACY_DECOMPRESSED_TOKEN_BYTES,
        )


def test_ambiguous_one_bit_fdict_neighbor_is_narrowly_fail_closed() -> None:
    ordinary_token = "CB2bFJ81qwcAB1kCgg"
    ambiguous_corruption = "CBybFJ81qwcAB1kCgg"
    service, _ = trusted_probe_service(
        valid_report(sdk_version=ordinary_token),
        evidence=empty_private_scan_evidence(),
    )
    assert decide_capability(service.probe()).outcome is CapabilityOutcome.ACCEPTED

    service, _ = trusted_probe_service(
        valid_report(sdk_version=ambiguous_corruption),
        evidence=empty_private_scan_evidence(),
    )
    with pytest.raises(capability_module.PrivacyScanUnavailable, match="preset dictionary"):
        service.probe()


def test_zlib_preset_dictionary_header_without_a_frame_is_a_benign_token() -> None:
    token = "eLs"
    assert base64.urlsafe_b64decode(token + "=") == b"\x78\xbb"
    assert capability_module._decode_canonical_zlib_base64url_with_work(
        token,
        max_output_bytes=capability_module._MAX_PRIVACY_DECOMPRESSED_TOKEN_BYTES,
    ) == (None, (), 0)
    service, _ = trusted_probe_service(
        valid_report(sdk_version=token),
        evidence=empty_private_scan_evidence(),
    )

    assert decide_capability(service.probe()).outcome is CapabilityOutcome.ACCEPTED


@pytest.mark.parametrize("nested", (False, True))
def test_valid_empty_preset_dictionary_frame_fails_closed(nested: bool) -> None:
    compressor = zlib.compressobj(level=9, wbits=zlib.MAX_WBITS, zdict=b"dictionary")
    complete = compressor.compress(b"") + compressor.flush()
    assert len(complete) == 12
    assert complete[1] & 0x20
    assert complete[2:6] == zlib.adler32(b"dictionary").to_bytes(4, "big")
    token = (
        _zlib_base64url_token(complete)
        if nested
        else base64.urlsafe_b64encode(complete).rstrip(b"=").decode("ascii")
    )
    service, _ = trusted_probe_service(
        valid_report(sdk_version=token),
        evidence=empty_private_scan_evidence(),
    )

    with pytest.raises(capability_module.PrivacyScanUnavailable, match="preset dictionary"):
        service.probe()


@pytest.mark.parametrize("truncated_length", range(2, 12))
def test_zlib_truncated_preset_dictionary_candidate_below_frame_minimum_is_benign(
    truncated_length: int,
) -> None:
    complete = bytes.fromhex("78f922ef0f0a431537343206003ae005f9")
    token = base64.urlsafe_b64encode(complete[:truncated_length]).rstrip(b"=").decode("ascii")
    decoded, _, _ = capability_module._decode_canonical_zlib_base64url_with_work(
        token,
        max_output_bytes=capability_module._MAX_PRIVACY_DECOMPRESSED_TOKEN_BYTES,
    )
    assert decoded is None
    service, _ = trusted_probe_service(
        valid_report(sdk_version=token),
        evidence=empty_private_scan_evidence(),
    )

    assert decide_capability(service.probe()).outcome is CapabilityOutcome.ACCEPTED


@pytest.mark.parametrize("nested", (False, True))
@pytest.mark.parametrize("removed_trailer_bytes", (1, 2, 3, 4))
def test_exact_fdict_frame_with_truncated_trailer_fails_closed(
    nested: bool,
    removed_trailer_bytes: int,
) -> None:
    complete = bytes.fromhex("78f922ef0f0a431537343206003ae005f9")
    truncated = complete[:-removed_trailer_bytes]
    assert len(truncated) >= capability_module._MIN_PRIVACY_FDICT_FRAME_BYTES
    token = (
        _zlib_base64url_token(truncated)
        if nested
        else base64.urlsafe_b64encode(truncated).rstrip(b"=").decode("ascii")
    )
    service, _ = trusted_probe_service(
        valid_report(sdk_version=token),
        evidence=empty_private_scan_evidence(),
    )

    with pytest.raises(capability_module.PrivacyScanUnavailable, match="preset dictionary"):
        service.probe()


@pytest.mark.parametrize("nested", (False, True))
def test_exact_fdict_frame_with_partial_deflate_output_fails_closed(nested: bool) -> None:
    compressor = zlib.compressobj(
        level=9,
        wbits=zlib.MAX_WBITS,
        zdict=b"common-prefix-family-secret-dictionary",
    )
    complete = compressor.compress(b"a" * 10_000) + compressor.flush()
    truncated = complete[:-5]
    assert len(truncated) >= capability_module._MIN_PRIVACY_FDICT_FRAME_BYTES
    token = (
        _zlib_base64url_token(truncated)
        if nested
        else base64.urlsafe_b64encode(truncated).rstrip(b"=").decode("ascii")
    )
    service, _ = trusted_probe_service(
        valid_report(sdk_version=token),
        evidence=empty_private_scan_evidence(),
    )

    with pytest.raises(capability_module.PrivacyScanUnavailable, match="preset dictionary"):
        service.probe()


def test_exact_fdict_header_with_zero_structural_progress_is_benign() -> None:
    benign = b"\x78\xf9" + b"\x00\x00\x00\x01" + b"\x06PUBLIC"
    assert len(benign) >= capability_module._MIN_PRIVACY_FDICT_FRAME_BYTES
    assert capability_module._inspect_preset_dictionary_frame(
        benign,
        max_output_bytes=capability_module._MAX_PRIVACY_DECOMPRESSED_TOKEN_BYTES,
    ) == (False, 0)
    token = base64.urlsafe_b64encode(benign).rstrip(b"=").decode("ascii")
    service, _ = trusted_probe_service(
        valid_report(sdk_version=token),
        evidence=empty_private_scan_evidence(),
    )

    assert decide_capability(service.probe()).outcome is CapabilityOutcome.ACCEPTED


@pytest.mark.parametrize(
    "encode_inner",
    (
        pytest.param(lambda value: value, id="raw"),
        pytest.param(base64.b64encode, id="base64"),
        pytest.param(
            lambda value: base64.urlsafe_b64encode(value).rstrip(b"="),
            id="base64url-unpadded",
        ),
    ),
)
def test_one_zlib_layer_rejects_preset_dictionary_stream(
    encode_inner: Callable[[bytes], bytes],
) -> None:
    preset_dictionary = b"common-prefix-family-secret-dictionary"
    compressor = zlib.compressobj(level=9, wbits=zlib.MAX_WBITS, zdict=preset_dictionary)
    inner = compressor.compress(b"family-secret-123") + compressor.flush()
    service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(b"X" + encode_inner(inner) + b"X")),
        evidence=empty_private_scan_evidence(),
    )

    with pytest.raises(capability_module.PrivacyScanUnavailable, match="preset dictionary"):
        service.probe()


def test_zlib_corrupt_outer_header_fallback_survives_incidental_later_header() -> None:
    token = "eNtjKT5ho2fEPH-2zpyj-eV5qUUu-hOnzwhbdufIt_frAbGPDjQ"
    _, recovered_payloads, _ = capability_module._decode_canonical_zlib_base64url_with_work(
        token,
        max_output_bytes=capability_module._MAX_PRIVACY_DECOMPRESSED_TOKEN_BYTES,
    )
    assert any(b"owner" in payload for payload in recovered_payloads)

    private_service, _ = trusted_probe_service(
        valid_report(sdk_version=token),
        evidence=empty_private_scan_evidence(principals=("owner",)),
    )
    with pytest.raises(capability_module.PrivacyScanRejected):
        private_service.probe()

    unrelated_service, _ = trusted_probe_service(
        valid_report(sdk_version=token),
        evidence=empty_private_scan_evidence(principals=("unrelated",)),
    )
    assert decide_capability(unrelated_service.probe()).outcome is CapabilityOutcome.ACCEPTED


def test_zlib_checksumless_frame_does_not_cover_a_following_real_frame() -> None:
    private_value = b"\x01" * 16
    framed = bytes.fromhex("789d0300789c636444050000980011")
    token = base64.urlsafe_b64encode(framed).rstrip(b"=").decode("ascii")
    assert token == "eJ0DAHicY2REBQAAmAAR"
    _, recovered_payloads, _ = capability_module._decode_canonical_zlib_base64url_with_work(
        token,
        max_output_bytes=capability_module._MAX_PRIVACY_DECOMPRESSED_TOKEN_BYTES,
    )
    assert private_value in recovered_payloads

    service, _ = trusted_probe_service(
        valid_report(sdk_version=token),
        evidence=empty_private_scan_evidence(content_buffers=(private_value,)),
    )
    with pytest.raises(capability_module.PrivacyScanRejected):
        service.probe()


def test_zlib_plausible_prefix_cannot_cover_an_overlapping_supported_frame() -> None:
    private_value = bytes.fromhex("ed8bcbbd52c4a5746f776e657230c4827f")
    framed = bytes.fromhex("0878da7bdb7d7a6fd091a525f9e579a94506479aea015b7a0950")
    token = base64.urlsafe_b64encode(framed).rstrip(b"=").decode("ascii")
    assert token == "CHjae9t9em_QkaUl-eV5qUUGR5rqAVt6CVA"
    _, recovered_payloads, _ = capability_module._decode_canonical_zlib_base64url_with_work(
        token,
        max_output_bytes=capability_module._MAX_PRIVACY_DECOMPRESSED_TOKEN_BYTES,
    )
    assert private_value in recovered_payloads

    private_service, _ = trusted_probe_service(
        valid_report(sdk_version=token),
        evidence=empty_private_scan_evidence(content_buffers=(private_value,)),
    )
    with pytest.raises(capability_module.PrivacyScanRejected):
        private_service.probe()

    unrelated_service, _ = trusted_probe_service(
        valid_report(sdk_version=token),
        evidence=empty_private_scan_evidence(content_buffers=(b"unrelated-public",)),
    )
    assert decide_capability(unrelated_service.probe()).outcome is CapabilityOutcome.ACCEPTED


def test_zlib_validated_trailer_cannot_cover_an_overlapping_second_frame() -> None:
    private_value = b"P" * 16
    token = "eJz7_3-AgAgAMvN4nAsIQAUAKpAFAQ"
    _, recovered_payloads, _ = capability_module._decode_canonical_zlib_base64url_with_work(
        token,
        max_output_bytes=capability_module._MAX_PRIVACY_DECOMPRESSED_TOKEN_BYTES,
    )
    assert private_value in recovered_payloads

    private_service, _ = trusted_probe_service(
        valid_report(sdk_version=token),
        evidence=empty_private_scan_evidence(content_buffers=(private_value,)),
    )
    with pytest.raises(capability_module.PrivacyScanRejected):
        private_service.probe()

    unrelated_service, _ = trusted_probe_service(
        valid_report(sdk_version=token),
        evidence=empty_private_scan_evidence(content_buffers=(b"unrelated-public",)),
    )
    assert decide_capability(unrelated_service.probe()).outcome is CapabilityOutcome.ACCEPTED


def test_zlib_decoder_attempts_every_bounded_plausible_offset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "eJz7_3-AgAgAMvN4nAsIQAUAKpAFAQ"
    compressed = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    plausible_offsets = tuple(
        offset
        for offset in range(len(compressed) - 1)
        if capability_module._has_bounded_zlib_header_candidate(compressed[offset:])
    )
    attempted_inputs: list[bytes] = []
    original = capability_module._recover_raw_deflate

    def recording_recovery(
        value: bytes,
        *,
        max_output_bytes: int,
    ) -> tuple[bytes | None, bool, bytes, int, int]:
        attempted_inputs.append(value)
        return original(value, max_output_bytes=max_output_bytes)

    monkeypatch.setattr(capability_module, "_recover_raw_deflate", recording_recovery)
    capability_module._decode_canonical_zlib_base64url_with_work(
        token,
        max_output_bytes=capability_module._MAX_PRIVACY_DECOMPRESSED_TOKEN_BYTES,
    )

    assert len(attempted_inputs) == len(plausible_offsets)


def test_zlib_prefixed_corrupt_header_is_found_at_a_nonzero_plausible_offset() -> None:
    private_value = b"x" * 1_024
    corrupt_frame = bytearray(zlib.compress(private_value))
    corrupt_frame[1] ^= 0x01
    token = base64.urlsafe_b64encode(b"X" + corrupt_frame).rstrip(b"=").decode("ascii")
    _, recovered_payloads, _ = capability_module._decode_canonical_zlib_base64url_with_work(
        token,
        max_output_bytes=capability_module._MAX_PRIVACY_DECOMPRESSED_TOKEN_BYTES,
    )
    assert private_value in recovered_payloads

    service, _ = trusted_probe_service(
        valid_report(sdk_version=token),
        evidence=empty_private_scan_evidence(content_buffers=(private_value,)),
    )
    with pytest.raises(capability_module.PrivacyScanRejected):
        service.probe()


@pytest.mark.parametrize("prefix", (b"\x00", b"X", b"junk"))
def test_zlib_prefixed_frame_is_recovered_and_scanned_with_bounded_offset_search(
    prefix: bytes,
) -> None:
    private_value = b"x" * 1_024
    prefixed_stream = prefix + zlib.compress(private_value)
    prefixed_token = base64.urlsafe_b64encode(prefixed_stream).rstrip(b"=").decode("ascii")
    assert (
        capability_module._decode_canonical_zlib_base64url(
            prefixed_token,
            max_output_bytes=len(private_value),
        )
        is None
    )

    private_service, _ = trusted_probe_service(
        valid_report(sdk_version=prefixed_token),
        evidence=empty_private_scan_evidence(content_buffers=(private_value,)),
    )
    with pytest.raises(capability_module.PrivacyScanRejected):
        private_service.probe()

    unrelated_service, _ = trusted_probe_service(
        valid_report(sdk_version=prefixed_token),
        evidence=empty_private_scan_evidence(content_buffers=(b"y" * 1_024,)),
    )
    assert decide_capability(unrelated_service.probe()).outcome is CapabilityOutcome.ACCEPTED


def test_zlib_decompression_aggregate_budget_accepts_exact_limit_only() -> None:
    capability_module._require_privacy_decompression_budget(
        token_output_bytes=capability_module._MAX_PRIVACY_DECOMPRESSED_TOKEN_BYTES,
        total_output_bytes=capability_module._MAX_PRIVACY_DECOMPRESSED_TOTAL_BYTES,
    )
    with pytest.raises(capability_module.PrivacyScanUnavailable, match="decompression bound"):
        capability_module._require_privacy_decompression_budget(
            token_output_bytes=capability_module._MAX_PRIVACY_DECOMPRESSED_TOKEN_BYTES + 1,
            total_output_bytes=capability_module._MAX_PRIVACY_DECOMPRESSED_TOTAL_BYTES,
        )
    with pytest.raises(capability_module.PrivacyScanUnavailable, match="decompression bound"):
        capability_module._require_privacy_decompression_budget(
            token_output_bytes=capability_module._MAX_PRIVACY_DECOMPRESSED_TOKEN_BYTES,
            total_output_bytes=capability_module._MAX_PRIVACY_DECOMPRESSED_TOTAL_BYTES + 1,
        )


def test_recovered_private_search_budget_accepts_exact_limit_only() -> None:
    capability_module._require_privacy_recovered_search_budget(
        capability_module._MAX_PRIVACY_RECOVERED_SEARCH_BYTES
    )
    with pytest.raises(capability_module.PrivacyScanUnavailable, match="recovered search bound"):
        capability_module._require_privacy_recovered_search_budget(
            capability_module._MAX_PRIVACY_RECOVERED_SEARCH_BYTES + 1
        )


def test_zlib_scan_counts_malformed_stream_output_against_aggregate_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(capability_module, "_MAX_PRIVACY_DECOMPRESSED_TOKEN_BYTES", 16)
    monkeypatch.setattr(capability_module, "_MAX_PRIVACY_DECOMPRESSED_TOTAL_BYTES", 16)
    exact_service, _ = trusted_probe_service(
        valid_report(
            sdk_version=_zlib_base64url_token(b"a" * 8),
            daemon_version=_zlib_base64url_token(b"b" * 8),
        ),
        evidence=empty_private_scan_evidence(),
    )
    assert decide_capability(exact_service.probe()).outcome is CapabilityOutcome.ACCEPTED

    trailing = (
        base64.urlsafe_b64encode(zlib.compress(b"c") + b"trailing").rstrip(b"=").decode("ascii")
    )
    over_service, _ = trusted_probe_service(
        valid_report(
            sdk_version=_zlib_base64url_token(b"a" * 16),
            daemon_version=trailing,
        ),
        evidence=empty_private_scan_evidence(),
    )
    with pytest.raises(capability_module.PrivacyScanUnavailable, match="decompression bound"):
        over_service.probe()


@pytest.mark.parametrize(
    ("evidence_field", "private_text"),
    (
        ("hostnames", "familybot"),
        ("fqdns", "home.lan"),
        ("ip_addresses", "10.0.0.1"),
        ("mac_addresses", "aa:bb:cc:dd:ee:ff"),
        ("principals", "owner"),
        ("home_paths", "/u/a"),
        ("serials", "s123"),
        ("ssids", "wifi"),
        ("fingerprints", "fp1234"),
    ),
)
def test_zlib_payload_scans_every_private_text_evidence_class(
    evidence_field: str,
    private_text: str,
) -> None:
    token = _zlib_base64url_token(f"x-{private_text}-x".encode())
    service, _ = trusted_probe_service(
        valid_report(sdk_version=token),
        evidence=empty_private_scan_evidence(**{evidence_field: (private_text,)}),
    )

    with pytest.raises(capability_module.PrivacyScanRejected):
        service.probe()


@pytest.mark.parametrize(
    "private_lexeme",
    ("xn--private", "192.168.1.2", "device.local", "hostname"),
)
def test_zlib_recovered_text_applies_static_public_token_privacy_guardrails(
    private_lexeme: str,
) -> None:
    service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(private_lexeme.encode())),
        evidence=empty_private_scan_evidence(),
    )

    with pytest.raises(capability_module.PrivacyScanRejected):
        service.probe()

    benign_service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(b"public-release")),
        evidence=empty_private_scan_evidence(),
    )
    assert decide_capability(benign_service.probe()).outcome is CapabilityOutcome.ACCEPTED


@pytest.mark.parametrize(
    ("evidence_field", "private_text"),
    (
        ("hostnames", "reachy"),
        ("principals", "runtime"),
        ("ssids", "host"),
        ("serials", "passed"),
    ),
)
def test_immutable_report_vocabulary_does_not_collide_with_private_evidence(
    evidence_field: str,
    private_text: str,
) -> None:
    service, _ = trusted_probe_service(
        valid_report(),
        evidence=empty_private_scan_evidence(**{evidence_field: (private_text,)}),
    )

    assert decide_capability(service.probe()).outcome is CapabilityOutcome.ACCEPTED


def test_probe_controlled_numeric_leaf_is_scanned_as_canonical_text() -> None:
    service, _ = trusted_probe_service(
        valid_report(memory_bytes=3_232_235_778),
        evidence=empty_private_scan_evidence(ip_addresses=("192.168.1.2",)),
    )

    with pytest.raises(capability_module.PrivacyScanRejected):
        service.probe()


def test_one_zlib_layer_scans_inner_lexical_encoding_and_rejects_nested_compression() -> None:
    private_bytes = b"\x01" * 16
    inner_base64 = base64.b64encode(private_bytes)
    service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(inner_base64)),
        evidence=empty_private_scan_evidence(content_buffers=(private_bytes,)),
    )
    with pytest.raises(capability_module.PrivacyScanRejected):
        service.probe()

    private_principal = "owner"
    encoded_principal_service, _ = trusted_probe_service(
        valid_report(
            sdk_version=_zlib_base64url_token(base64.b64encode(private_principal.encode("utf-8")))
        ),
        evidence=empty_private_scan_evidence(principals=(private_principal,)),
    )
    with pytest.raises(capability_module.PrivacyScanRejected):
        encoded_principal_service.probe()

    assert capability_module._MAX_PRIVACY_COMPRESSION_LAYERS == 1
    nested_service, _ = trusted_probe_service(
        valid_report(
            sdk_version=_zlib_base64url_token(zlib.compress(private_bytes)),
        ),
        evidence=empty_private_scan_evidence(content_buffers=(private_bytes,)),
    )
    with pytest.raises(capability_module.PrivacyScanUnavailable, match="nested compression"):
        nested_service.probe()


@pytest.mark.parametrize(
    ("private_bytes", "encode_private"),
    (
        pytest.param(b"\x00" * 33, lambda value: value.hex().encode("ascii"), id="hex"),
        pytest.param(b"\x00" * 49, base64.b64encode, id="base64"),
        pytest.param(
            b"\x00" * 49,
            lambda value: base64.urlsafe_b64encode(value).rstrip(b"="),
            id="base64url-unpadded",
        ),
        pytest.param(b"\x00\x01" * 21, base64.b32encode, id="base32"),
    ),
)
def test_zlib_recovered_long_reversible_binary_encoding_is_rejected(
    private_bytes: bytes,
    encode_private: Callable[[bytes], bytes],
) -> None:
    encoded_private = encode_private(private_bytes)
    assert len(encoded_private) > capability_module._MAX_PRIVACY_PUBLIC_TEXT_VALUE_BYTES
    service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(encoded_private)),
        evidence=empty_private_scan_evidence(content_buffers=(private_bytes,)),
    )

    with pytest.raises(capability_module.PrivacyScanRejected):
        service.probe()

    benign_service, _ = trusted_probe_service(
        valid_report(
            sdk_version=_zlib_base64url_token(encode_private(b"\x01" * len(private_bytes)))
        ),
        evidence=empty_private_scan_evidence(content_buffers=(private_bytes,)),
    )
    assert decide_capability(benign_service.probe()).outcome is CapabilityOutcome.ACCEPTED


def test_zlib_recovered_long_representation_work_bound_is_exact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_bytes = b"\x00" * 49
    benign_payload = base64.b64encode(b"\x01" * 49)
    evidence = empty_private_scan_evidence(content_buffers=(private_bytes,))
    expected_work = 134
    monkeypatch.setattr(
        capability_module,
        "_MAX_PRIVACY_RECOVERED_REPRESENTATION_BYTES",
        expected_work,
    )
    exact_service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(benign_payload)),
        evidence=evidence,
    )
    assert decide_capability(exact_service.probe()).outcome is CapabilityOutcome.ACCEPTED

    monkeypatch.setattr(
        capability_module,
        "_MAX_PRIVACY_RECOVERED_REPRESENTATION_BYTES",
        expected_work - 1,
    )
    over_service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(benign_payload)),
        evidence=evidence,
    )
    with pytest.raises(capability_module.PrivacyScanUnavailable, match="representation"):
        over_service.probe()


def test_long_reversible_containment_work_bound_is_exact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_source = b"\x00" * 49
    recovered = base64.b64encode(b"\x01" * 49)
    expected_work = 2 * len(recovered)
    monkeypatch.setattr(
        capability_module,
        "_MAX_PRIVACY_RECOVERED_SEARCH_BYTES",
        expected_work,
    )
    exact_budget = capability_module._RecoveredScanBudget()
    capability_module._scan_long_reversible_representations(
        recovered,
        (private_source,),
        budget=exact_budget,
    )
    assert exact_budget.comparison_bytes == expected_work

    monkeypatch.setattr(
        capability_module,
        "_MAX_PRIVACY_RECOVERED_SEARCH_BYTES",
        expected_work - 1,
    )
    with pytest.raises(capability_module.PrivacyScanUnavailable, match="recovered search bound"):
        capability_module._scan_long_reversible_representations(
            recovered,
            (private_source,),
            budget=capability_module._RecoveredScanBudget(),
        )


def test_zlib_recovered_long_lexical_nested_compression_fails_closed() -> None:
    private_bytes = b"x" * 100_000
    encoded_inner = base64.b64encode(zlib.compress(private_bytes))
    assert len(encoded_inner) > capability_module._MAX_PRIVACY_PUBLIC_TEXT_VALUE_BYTES
    outer_token = _zlib_base64url_token(encoded_inner)
    assert len(outer_token) <= capability_module._MAX_PRIVACY_PUBLIC_TEXT_VALUE_BYTES
    service, _ = trusted_probe_service(
        valid_report(sdk_version=outer_token),
        evidence=empty_private_scan_evidence(content_buffers=(private_bytes,)),
    )

    with pytest.raises(capability_module.PrivacyScanUnavailable, match="nested compression"):
        service.probe()


@pytest.mark.parametrize("invalid_position", ("prefix", "middle", "suffix"))
@pytest.mark.parametrize(
    ("private_evidence", "encoded_private"),
    (
        pytest.param(
            {"principals": ("owner",)},
            b"OWNER",
            id="private-text",
        ),
        pytest.param(
            {"principals": ("owner",)},
            base64.b64encode(b"owner"),
            id="private-text-base64",
        ),
        pytest.param(
            {"content_buffers": (b"private-buffer!!",)},
            b"private-buffer!!".hex().upper().encode("ascii"),
            id="private-binary-hex",
        ),
        pytest.param(
            {"content_buffers": (b"private-buffer!!",)},
            base64.b64encode(b"private-buffer!!"),
            id="private-binary-base64",
        ),
        pytest.param(
            {"content_buffers": (b"private-buffer!!",)},
            base64.b32encode(b"private-buffer!!"),
            id="private-binary-base32",
        ),
    ),
)
def test_zlib_recovered_lexical_scan_is_lossless_across_invalid_utf8(
    private_evidence: dict[str, tuple[object, ...]],
    encoded_private: bytes,
    invalid_position: str,
) -> None:
    insert_at = {
        "prefix": 0,
        "middle": len(encoded_private) // 2,
        "suffix": len(encoded_private),
    }[invalid_position]
    invalid_payload = encoded_private[:insert_at] + b"\xff" + encoded_private[insert_at:]
    service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(invalid_payload)),
        evidence=empty_private_scan_evidence(**private_evidence),
    )

    with pytest.raises(capability_module.PrivacyScanRejected):
        service.probe()


def test_zlib_recovered_text_preserves_multibyte_private_bytes_across_invalid_gap() -> None:
    private_text = "r\N{LATIN SMALL LETTER E WITH ACUTE}achy"
    private_bytes = private_text.encode()
    invalid_payload = b"x-" + private_bytes[:2] + b"\xff" + private_bytes[2:] + b"-x"
    service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(invalid_payload)),
        evidence=empty_private_scan_evidence(principals=(private_text,)),
    )

    with pytest.raises(capability_module.PrivacyScanRejected):
        service.probe()

    benign_service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(b"public-\xff-value")),
        evidence=empty_private_scan_evidence(principals=(private_text,)),
    )
    assert decide_capability(benign_service.probe()).outcome is CapabilityOutcome.ACCEPTED


@pytest.mark.parametrize("invalid_byte_count", (1, 2, 3, 4))
def test_zlib_utf8_repair_handles_the_declared_deletion_frontier(
    invalid_byte_count: int,
) -> None:
    private_text = "r\N{LATIN SMALL LETTER E WITH ACUTE}achy"
    private_bytes = private_text.encode()
    payload = b"x-" + private_bytes[:2] + b"\xff" * invalid_byte_count + private_bytes[2:] + b"-x"
    service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(payload)),
        evidence=empty_private_scan_evidence(principals=(private_text,)),
    )

    with pytest.raises(capability_module.PrivacyScanRejected):
        service.probe()


def test_zlib_utf8_repair_frontier_exhaustion_fails_closed() -> None:
    private_text = "r\N{LATIN SMALL LETTER E WITH ACUTE}achy"
    private_bytes = private_text.encode()
    irreparable_private = b"x-" + private_bytes[:2] + b"\xff" * 5 + private_bytes[2:] + b"-x"
    private_service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(irreparable_private)),
        evidence=empty_private_scan_evidence(principals=(private_text,)),
    )
    with pytest.raises(capability_module.PrivacyScanUnavailable, match="UTF-8 repair"):
        private_service.probe()

    benign_service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(b"public-" + b"\xff" * 5)),
        evidence=empty_private_scan_evidence(principals=(private_text,)),
    )
    with pytest.raises(capability_module.PrivacyScanUnavailable, match="UTF-8 repair"):
        benign_service.probe()


@pytest.mark.parametrize(
    "encoded_inner",
    (
        pytest.param(lambda value: value.hex().encode("ascii"), id="hex"),
        pytest.param(base64.b64encode, id="base64"),
        pytest.param(
            lambda value: base64.urlsafe_b64encode(value).rstrip(b"="),
            id="base64url-unpadded",
        ),
        pytest.param(base64.b32encode, id="base32"),
    ),
)
def test_one_zlib_layer_rejects_lexically_encoded_nested_zlib(
    encoded_inner: Callable[[bytes], bytes],
) -> None:
    private_bytes = b"\x01" * 16
    inner_zlib = zlib.compress(private_bytes)
    inner_representation = encoded_inner(inner_zlib)
    assert len(inner_representation) <= capability_module._MAX_PRIVACY_PUBLIC_TEXT_VALUE_BYTES
    service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(inner_representation)),
        evidence=empty_private_scan_evidence(content_buffers=(private_bytes,)),
    )

    with pytest.raises(capability_module.PrivacyScanUnavailable, match="nested compression"):
        service.probe()


@pytest.mark.parametrize("wrapper", (lambda value: b"X" + value, lambda value: value + b"X"))
@pytest.mark.parametrize(
    "encode_inner",
    (
        pytest.param(lambda value: value.hex().encode("ascii"), id="hex"),
        pytest.param(base64.b64encode, id="base64"),
        pytest.param(base64.b32encode, id="base32"),
    ),
)
def test_one_zlib_layer_rejects_wrapped_lexically_encoded_nested_zlib(
    encode_inner: Callable[[bytes], bytes],
    wrapper: Callable[[bytes], bytes],
) -> None:
    private_bytes = b"\x01" * 16
    wrapped_inner = wrapper(encode_inner(zlib.compress(private_bytes)))
    service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(wrapped_inner)),
        evidence=empty_private_scan_evidence(content_buffers=(private_bytes,)),
    )

    with pytest.raises(capability_module.PrivacyScanUnavailable, match="nested compression"):
        service.probe()


@pytest.mark.parametrize("prefix", (b"X", b"junk"))
def test_one_zlib_layer_rejects_prefixed_raw_nested_zlib(prefix: bytes) -> None:
    private_bytes = b"\x01" * 16
    service, _ = trusted_probe_service(
        valid_report(
            sdk_version=_zlib_base64url_token(prefix + zlib.compress(private_bytes)),
        ),
        evidence=empty_private_scan_evidence(content_buffers=(private_bytes,)),
    )

    with pytest.raises(capability_module.PrivacyScanUnavailable, match="nested compression"):
        service.probe()


@pytest.mark.parametrize(
    "encode_inner",
    (
        pytest.param(lambda value: value, id="raw"),
        pytest.param(lambda value: value.hex().encode("ascii"), id="hex"),
        pytest.param(base64.b64encode, id="base64"),
        pytest.param(
            lambda value: base64.urlsafe_b64encode(value).rstrip(b"="),
            id="base64url-unpadded",
        ),
        pytest.param(base64.b32encode, id="base32"),
    ),
)
def test_one_zlib_layer_rejects_corrupt_nested_zlib_variants(
    encode_inner: Callable[[bytes], bytes],
) -> None:
    private_bytes = b"\x01" * 16
    corrupt_inner = bytearray(zlib.compress(private_bytes))
    corrupt_inner[1] ^= 0x01
    service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(encode_inner(bytes(corrupt_inner)))),
        evidence=empty_private_scan_evidence(content_buffers=(private_bytes,)),
    )

    with pytest.raises(capability_module.PrivacyScanUnavailable, match="nested compression"):
        service.probe()


def test_one_zlib_layer_allows_plausible_header_that_is_not_a_deflate_stream() -> None:
    for public_payload in (
        b"\x78\x9dnot-deflate",
        b"public-\x78\x9c-nope",
        b"release-eJw-build",
    ):
        service, _ = trusted_probe_service(
            valid_report(sdk_version=_zlib_base64url_token(public_payload)),
            evidence=empty_private_scan_evidence(),
        )

        assert decide_capability(service.probe()).outcome is CapabilityOutcome.ACCEPTED


def test_one_zlib_layer_allows_wrapped_lexical_non_zlib_near_miss() -> None:
    public_payload = b"X" + base64.b64encode(b"not-zlib") + b"X"
    service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(public_payload)),
        evidence=empty_private_scan_evidence(),
    )

    assert decide_capability(service.probe()).outcome is CapabilityOutcome.ACCEPTED


@pytest.mark.parametrize("wrapper", (lambda value: value, lambda value: b"X" + value + b"X"))
@pytest.mark.parametrize(
    "encode_public",
    (
        pytest.param(lambda value: value, id="raw"),
        pytest.param(lambda value: value.hex().encode("ascii"), id="hex"),
        pytest.param(base64.b64encode, id="base64"),
        pytest.param(
            lambda value: base64.urlsafe_b64encode(value).rstrip(b"="),
            id="base64url-unpadded",
        ),
        pytest.param(base64.b32encode, id="base32"),
    ),
)
def test_complete_non_zlib_near_miss_has_encoding_parity(
    encode_public: Callable[[bytes], bytes],
    wrapper: Callable[[bytes], bytes],
) -> None:
    invalid_stream = b"\x78\x9cnot-deflate"
    service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(wrapper(encode_public(invalid_stream)))),
        evidence=empty_private_scan_evidence(),
    )

    assert decide_capability(service.probe()).outcome is CapabilityOutcome.ACCEPTED


@pytest.mark.parametrize(
    "encode_public",
    (
        pytest.param(lambda value: value.hex().encode("ascii"), id="hex"),
        pytest.param(base64.b64encode, id="base64"),
        pytest.param(base64.b32encode, id="base32"),
    ),
)
def test_nested_lexical_header_detection_has_non_zlib_near_misses(
    encode_public: Callable[[bytes], bytes],
) -> None:
    public_payload = b"X" + encode_public(b"not-zlib") + b"X"
    contains_nested, _ = capability_module._contains_nested_zlib(
        public_payload,
        search_bytes=0,
    )
    assert not contains_nested


def test_nested_lexical_header_detection_covers_every_supported_header() -> None:
    canonical_frame = zlib.compress(b"x")
    for header in capability_module._SUPPORTED_ZLIB_HEADERS:
        complete_frame = header + canonical_frame[2:]
        for encoded_prefix in (
            complete_frame,
            complete_frame.hex().encode("ascii"),
            base64.b64encode(complete_frame),
            base64.urlsafe_b64encode(complete_frame).rstrip(b"="),
            base64.b32encode(complete_frame),
        ):
            contains_nested, _ = capability_module._contains_nested_zlib(
                b"X" + encoded_prefix + b"X",
                search_bytes=0,
            )
            assert contains_nested


def test_nested_fdict_structural_attempt_bound_is_exact() -> None:
    malformed_candidate = bytes.fromhex("78f906")
    exact = malformed_candidate * capability_module._MAX_PRIVACY_NESTED_RECOVERY_ATTEMPTS
    assert capability_module._contains_nested_zlib(exact, search_bytes=0)[0] is False

    over = exact + malformed_candidate
    with pytest.raises(capability_module.PrivacyScanUnavailable, match="nested transform bound"):
        capability_module._contains_nested_zlib(over, search_bytes=0)


@pytest.mark.parametrize(
    "encode_private",
    (
        pytest.param(lambda value: value.hex().encode("ascii"), id="hex"),
        pytest.param(base64.b64encode, id="base64"),
        pytest.param(base64.b32encode, id="base32"),
    ),
)
@pytest.mark.parametrize(
    ("private_text", "normalized_text"),
    (
        pytest.param("Owner", "owner", id="casefold"),
        pytest.param(
            "re\N{COMBINING ACUTE ACCENT}achy",
            "r\N{LATIN SMALL LETTER E WITH ACUTE}achy",
            id="nfkc",
        ),
    ),
)
def test_zlib_lexical_encoding_scan_includes_normalized_private_text_sources(
    encode_private: Callable[[bytes], bytes],
    private_text: str,
    normalized_text: str,
) -> None:
    assert unicodedata.normalize("NFKC", private_text).casefold() == normalized_text
    encoded_private = encode_private(normalized_text.encode("utf-8"))
    service, _ = trusted_probe_service(
        valid_report(sdk_version=_zlib_base64url_token(encoded_private)),
        evidence=empty_private_scan_evidence(principals=(private_text,)),
    )

    with pytest.raises(capability_module.PrivacyScanRejected):
        service.probe()


def test_nested_lexical_search_budget_accepts_exact_limit_only() -> None:
    capability_module._require_privacy_nested_search_budget(
        capability_module._MAX_PRIVACY_NESTED_SEARCH_BYTES
    )
    with pytest.raises(capability_module.PrivacyScanUnavailable, match="nested search bound"):
        capability_module._require_privacy_nested_search_budget(
            capability_module._MAX_PRIVACY_NESTED_SEARCH_BYTES + 1
        )


def test_nested_lexical_prefix_work_is_charged_to_the_aggregate_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(capability_module, "_MAX_PRIVACY_NESTED_DECODE_ATTEMPTS", 3)

    with pytest.raises(capability_module.PrivacyScanUnavailable, match="transform bound"):
        capability_module._contains_nested_zlib(b"public", search_bytes=0)


@pytest.mark.parametrize("evidence_field", ("principals", "serials", "ssids"))
def test_short_private_text_does_not_collide_with_unrelated_report_substrings(
    evidence_field: str,
) -> None:
    service, _ = trusted_probe_service(
        valid_report(),
        evidence=empty_private_scan_evidence(**{evidence_field: ("a",)}),
    )

    assert decide_capability(service.probe()).outcome is CapabilityOutcome.ACCEPTED


def test_private_text_matching_uses_exact_values_below_substring_threshold() -> None:
    threshold = capability_module._MIN_PRIVACY_SUBSTRING_TEXT_CHARACTERS
    assert threshold == 4
    short_private = "a" * (threshold - 1)
    exact_service, _ = trusted_probe_service(
        valid_report(sdk_version=short_private),
        evidence=empty_private_scan_evidence(principals=(short_private,)),
    )
    with pytest.raises(capability_module.PrivacyScanRejected):
        exact_service.probe()

    embedded_short_service, _ = trusted_probe_service(
        valid_report(sdk_version=f"x{short_private}x"),
        evidence=empty_private_scan_evidence(principals=(short_private,)),
    )
    assert decide_capability(embedded_short_service.probe()).outcome is CapabilityOutcome.ACCEPTED

    threshold_private = "a" * threshold
    embedded_threshold_service, _ = trusted_probe_service(
        valid_report(sdk_version=f"x{threshold_private}x"),
        evidence=empty_private_scan_evidence(principals=(threshold_private,)),
    )
    with pytest.raises(capability_module.PrivacyScanRejected):
        embedded_threshold_service.probe()


@pytest.mark.parametrize("dependency_count", (20, 30, 128))
def test_contract_max_dependency_inventory_passes_bounded_privacy_scan(
    dependency_count: int,
) -> None:
    dependencies = dependency_inventory(dependency_count)
    service, _ = trusted_probe_service(
        valid_report(
            dependencies=dependencies,
            runtime_inventory_sha256=capability_module._runtime_inventory_sha256(dependencies),
        ),
        evidence=empty_private_scan_evidence(),
    )

    probed = service.probe()

    assert probed.report.runtime.dependencies is not None
    assert len(probed.report.runtime.dependencies) == dependency_count


def test_max_inventory_uses_the_exact_probe_controlled_report_leaf_bound() -> None:
    dependencies = dependency_inventory(128)
    service, _ = trusted_probe_service(
        valid_report(
            dependencies=dependencies,
            runtime_inventory_sha256=capability_module._runtime_inventory_sha256(dependencies),
        ),
        evidence=empty_private_scan_evidence(),
    )
    report = service.probe().report

    values = capability_module._report_privacy_values(report)

    assert len(values) == capability_module._MAX_PRIVACY_REPORT_TEXT_VALUES == 263


@pytest.mark.parametrize("evidence_field", ("key_material", "content_buffers"))
def test_binary_privacy_evidence_enforces_realistic_class_minimums(
    evidence_field: str,
) -> None:
    minimum = 16
    with pytest.raises(ValueError, match="minimum"):
        empty_private_scan_evidence(**{evidence_field: (b"x" * (minimum - 1),)})

    accepted = empty_private_scan_evidence(**{evidence_field: (b"x" * minimum,)})

    assert getattr(accepted, evidence_field) == (b"x" * minimum,)


def test_probe_service_owns_the_report_and_rejects_injection_surfaces() -> None:
    report = valid_report()
    service, _ = trusted_probe_service(report)

    probed = service.probe()

    assert probed.report == report
    assert decide_capability(probed).outcome is CapabilityOutcome.ACCEPTED
    with pytest.raises(TypeError):
        service.probe(report)
    with pytest.raises(TypeError):
        capability_module.CapabilityProbeService(lambda: report)
    with pytest.raises(TypeError):
        capability_module.TrustedCapabilityProducer(lambda: report)
    with pytest.raises(TypeError):
        capability_module.MediaObservationBuilder(report.media)
    with pytest.raises(TypeError):
        capability_module.RuntimeVersionObservation(
            source=capability_module.RuntimeVersionSource.PACKAGE_METADATA,
            raw=b"1.2.3\n",
        )


@pytest.mark.parametrize(
    "transformed_private",
    (
        hashlib.sha256(b"family-secret").hexdigest(),
        hmac.new(b"probe-key", b"family-secret", hashlib.sha256).hexdigest(),
        base64.urlsafe_b64encode(b"family-secret").rstrip(b"=").decode("ascii"),
        b"family-secret".hex(),
        b"family-secret"[::-1].decode("ascii"),
    ),
)
def test_transformed_private_values_cannot_be_injected_into_a_trusted_snapshot(
    transformed_private: str,
) -> None:
    service, _ = trusted_probe_service(valid_report())
    alternate = valid_report(sdk_version=transformed_private)

    with pytest.raises(TypeError):
        service.probe(alternate)
    assert decide_capability(alternate).rejection_reasons == (
        RejectionReason.REPORT_PRIVACY_FAILED,
    )

    probed = service.probe()
    object.__setattr__(probed, "_report_raw", capability_module.canonical_bytes(alternate))
    assert decide_capability(probed).rejection_reasons == (RejectionReason.REPORT_PRIVACY_FAILED,)


def test_runtime_builder_computes_sanctioned_hash_and_inventory_leaves() -> None:
    report = valid_report()
    service, producer = trusted_probe_service(report)
    del service

    built = producer.runtime_observation

    assert built.sdk_artifact_sha256 == hashlib.sha256(SDK_ARTIFACT).hexdigest()
    assert built.daemon_artifact_sha256 == hashlib.sha256(DAEMON_ARTIFACT).hexdigest()
    assert built.dependencies is not None
    assert built.dependencies[0].artifact_sha256 == hashlib.sha256(DEPENDENCY_ARTIFACT).hexdigest()
    with pytest.raises(TypeError):
        capability_module.RuntimeObservationBuilder(
            report.runtime,
            sdk_artifact_sha256=hashlib.sha256(b"private-value").hexdigest(),
        )


def test_runtime_builder_enforces_dependency_count_before_hashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sdk = runtime_artifact_observation("reachy-sdk", b"s")
    daemon = runtime_artifact_observation(
        "reachy-daemon",
        b"d",
        source=capability_module.RuntimeVersionSource.DAEMON_PROTOCOL,
    )
    exact = tuple(runtime_artifact_observation(f"dep-{index:03d}", b"x") for index in range(128))

    built = build_runtime_observation(
        sdk_artifact=sdk,
        daemon_artifact=daemon,
        dependencies=exact,
    )
    assert len(built.observation.dependencies) == 128

    one_too_many = (*exact, runtime_artifact_observation("dep-128", b"x"))

    def unexpected_hash(*args: object, **kwargs: object) -> object:
        raise AssertionError("dependency count must be checked before hashing")

    monkeypatch.setattr(capability_module.hashlib, "sha256", unexpected_hash)
    with pytest.raises(ValueError, match="dependency count"):
        build_runtime_observation(
            sdk_artifact=sdk,
            daemon_artifact=daemon,
            dependencies=one_too_many,
        )


def test_runtime_builder_enforces_256_mib_total_before_hashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_limit = capability_module._MAX_RUNTIME_ARTIFACT_BYTES
    assert artifact_limit * 4 == 256 * 1024 * 1024
    shared = b"x" * artifact_limit
    sdk = runtime_artifact_observation("reachy-sdk", shared)
    daemon = runtime_artifact_observation(
        "reachy-daemon",
        shared,
        source=capability_module.RuntimeVersionSource.DAEMON_PROTOCOL,
    )
    exact_dependencies = (
        runtime_artifact_observation("dep-000", shared),
        runtime_artifact_observation("dep-001", shared),
    )

    build_runtime_observation(
        sdk_artifact=sdk,
        daemon_artifact=daemon,
        dependencies=exact_dependencies,
    )
    one_too_many = (
        *exact_dependencies,
        runtime_artifact_observation("dep-002", b"x"),
    )

    def unexpected_hash(*args: object, **kwargs: object) -> object:
        raise AssertionError("artifact total must be checked before hashing")

    monkeypatch.setattr(capability_module.hashlib, "sha256", unexpected_hash)
    with pytest.raises(ValueError, match="aggregate artifact"):
        build_runtime_observation(
            sdk_artifact=sdk,
            daemon_artifact=daemon,
            dependencies=one_too_many,
        )


def test_runtime_builder_documents_streaming_collector_boundary() -> None:
    assert "stream" in (capability_module.RuntimeObservationBuilder.__doc__ or "").casefold()


@pytest.mark.parametrize(
    ("artifact_role", "wrong_source"),
    (
        ("sdk", capability_module.RuntimeVersionSource.DAEMON_PROTOCOL),
        ("daemon", capability_module.RuntimeVersionSource.PACKAGE_METADATA),
        ("dependency", capability_module.RuntimeVersionSource.DAEMON_PROTOCOL),
    ),
)
def test_runtime_builder_rejects_version_evidence_from_the_wrong_concrete_source(
    artifact_role: str,
    wrong_source: object,
) -> None:
    constructor = capability_module._COMPOSITION_ROOT_CONSTRUCTOR

    def artifact(
        distribution: str,
        source: object,
        content: bytes,
    ) -> object:
        return capability_module.RuntimeArtifactObservation(
            distribution=distribution,
            version=capability_module.RuntimeVersionObservation(
                source=source,
                raw=b"1.2.3\n",
                constructor=constructor,
            ),
            artifact=content,
            constructor=constructor,
        )

    unobserved = capability_module.UnobservedEvidence(
        observation="unobserved",
        reason=UnobservedReason.NOT_ATTEMPTED,
    )
    observed = capability_module.ObservedEvidence(observation="observed")
    sdk_artifact = None
    daemon_artifact = None
    dependencies = None
    daemon_evidence = unobserved
    sdk_evidence = unobserved
    if artifact_role == "sdk":
        sdk_artifact = artifact("reachy-sdk", wrong_source, SDK_ARTIFACT)
        sdk_evidence = observed
        dependencies = ()
    elif artifact_role == "daemon":
        daemon_artifact = artifact("reachy-daemon", wrong_source, DAEMON_ARTIFACT)
        daemon_evidence = observed
    else:
        sdk_artifact = artifact(
            "reachy-sdk",
            capability_module.RuntimeVersionSource.PACKAGE_METADATA,
            SDK_ARTIFACT,
        )
        sdk_evidence = observed
        dependencies = (artifact("synthetic-media", wrong_source, DEPENDENCY_ARTIFACT),)

    with pytest.raises(ValueError, match="source"):
        capability_module.RuntimeObservationBuilder(
            constructor=constructor,
            daemon_evidence=daemon_evidence,
            sdk_evidence=sdk_evidence,
            interpreter_evidence=unobserved,
            sdk_artifact=sdk_artifact,
            daemon_artifact=daemon_artifact,
            interpreter=None,
            dependencies=dependencies,
            daemon_available=CheckStatus.UNKNOWN,
            sdk_daemon_match=CheckStatus.UNKNOWN,
            interpreter_supported=CheckStatus.UNKNOWN,
        )


def test_private_digest_cannot_be_substituted_for_a_sanctioned_artifact_hash() -> None:
    report = valid_report()
    service, _ = trusted_probe_service(report)
    alternate = valid_report(
        sdk_artifact_sha256=hashlib.sha256(b"family-secret").hexdigest(),
    )

    with pytest.raises(TypeError):
        service.probe(alternate)
    assert decide_capability(alternate).rejection_reasons == (
        RejectionReason.REPORT_PRIVACY_FAILED,
    )

    probed = service.probe()
    object.__setattr__(probed, "_report_raw", capability_module.canonical_bytes(alternate))
    assert decide_capability(probed).rejection_reasons == (RejectionReason.REPORT_PRIVACY_FAILED,)


def test_malformed_raw_report_substitution_fails_closed_without_parsing_details() -> None:
    service, _ = trusted_probe_service(valid_report())
    probed = service.probe()
    object.__setattr__(probed, "_report_raw", b'{"private":"family-secret"}')

    decision = decide_capability(probed)

    assert decision.outcome is CapabilityOutcome.REJECTED
    assert decision.rejection_reasons == (RejectionReason.REPORT_PRIVACY_FAILED,)


def test_probed_capability_rejects_cross_producer_cross_run_and_report_substitution() -> None:
    report = valid_report()
    first_service, _ = trusted_probe_service(report)
    second_service, _ = trusted_probe_service(report)
    first_run = first_service.probe()
    second_run = first_service.probe()
    other_producer = second_service.probe()

    object.__setattr__(first_run, "_provenance", second_run._provenance)
    object.__setattr__(second_run, "_provenance", other_producer._provenance)
    changed = valid_report(temperature_millicelsius=45_001)
    object.__setattr__(other_producer, "_report_raw", capability_module.canonical_bytes(changed))

    for substituted in (first_run, second_run, other_producer):
        decision = decide_capability(substituted)
        assert decision.outcome is CapabilityOutcome.REJECTED
        assert decision.rejection_reasons == (RejectionReason.REPORT_PRIVACY_FAILED,)

    fresh, _ = trusted_probe_service(report)
    tampered_sequence = fresh.probe()
    tampered_snapshot = fresh.probe()
    object.__setattr__(
        tampered_sequence._provenance,
        "sequence",
        tampered_sequence._provenance.sequence + 1,
    )
    object.__setattr__(tampered_snapshot._provenance, "snapshot_identity", object())
    for tampered in (tampered_sequence, tampered_snapshot):
        assert decide_capability(tampered).rejection_reasons == (
            RejectionReason.REPORT_PRIVACY_FAILED,
        )


def test_snapshot_is_consumed_on_rejection_and_cannot_be_replayed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = valid_report(sdk_version="opaque-release")
    evidence = private_scan_evidence(serials=("opaque-release",))
    service, producer = trusted_probe_service(report, evidence=evidence)

    with pytest.raises(capability_module.PrivacyScanRejected):
        service.probe()

    assert producer.outstanding_snapshot_count == 0
    assert producer.last_consumed_sequence == 1
    stale_snapshot = producer._capture(capability_module._TRUSTED_CAPTURE_CONSTRUCTOR)
    producer._consume(stale_snapshot, capability_module._TRUSTED_CAPTURE_CONSTRUCTOR)
    monkeypatch.setattr(
        capability_module.TrustedCapabilityProducer,
        "_capture",
        lambda self, constructor: stale_snapshot,
    )
    with pytest.raises(capability_module.PrivacyScanUnavailable, match="snapshot"):
        service.probe()


def test_exhausted_snapshot_sequence_fails_closed_without_leaving_a_snapshot() -> None:
    service, producer = trusted_probe_service(valid_report())
    producer._next_sequence = (1 << 64) - 1

    final_snapshot = service.probe()

    assert final_snapshot._provenance.sequence == (1 << 64) - 1
    assert producer.last_consumed_sequence == (1 << 64) - 1

    with pytest.raises(capability_module.PrivacyScanUnavailable, match="sequence"):
        service.probe()

    assert producer.outstanding_snapshot_count == 0
    assert producer.last_consumed_sequence == (1 << 64) - 1


@pytest.mark.parametrize(
    "incomplete_status",
    (
        capability_module.PrivacyCollectionStatus.PARTIAL,
        capability_module.PrivacyCollectionStatus.ERROR,
    ),
)
def test_partial_or_error_privacy_snapshots_are_rejected_and_consumed(
    incomplete_status: object,
) -> None:
    evidence = private_scan_evidence()
    coverage = list(evidence.coverage)
    coverage[0] = capability_module.PrivacyEvidenceCoverage(
        evidence_class=capability_module.PrivacyEvidenceClass.HOSTNAME,
        acquisition_source=capability_module.PrivacyAcquisitionSource.SOCKET_IDENTITY,
        status=incomplete_status,
    )
    object.__setattr__(evidence, "coverage", tuple(coverage))
    service, producer = trusted_probe_service(valid_report(), evidence=evidence)

    with pytest.raises(capability_module.PrivacyScanUnavailable):
        service.probe()

    assert producer.outstanding_snapshot_count == 0
    assert producer.last_consumed_sequence == 1


def test_probe_detects_report_toctou_and_consumes_the_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, producer = trusted_probe_service(valid_report())
    real_scan = capability_module._scan_privacy_snapshot

    def scan_then_drift(report: ReachyCapabilityReportV1, evidence: object) -> None:
        real_scan(report, evidence)
        object.__setattr__(report.host, "temperature_millicelsius", 45_001)

    monkeypatch.setattr(capability_module, "_scan_privacy_snapshot", scan_then_drift)

    with pytest.raises(capability_module.PrivacyScanUnavailable, match="source drift"):
        service.probe()

    assert producer.outstanding_snapshot_count == 0


def test_probe_detects_evidence_toctou_and_deep_owns_source_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = valid_report()
    evidence = private_scan_evidence()
    service, producer = trusted_probe_service(report, evidence=evidence)
    object.__setattr__(report.host, "temperature_millicelsius", 99_999)
    object.__setattr__(evidence, "serials", ("mutated-after-construction",))

    assert service.probe().report.host.temperature_millicelsius == 45_000

    real_scan = capability_module._scan_privacy_snapshot

    def scan_then_drift(
        snapshot_report: ReachyCapabilityReportV1, snapshot_evidence: object
    ) -> None:
        real_scan(snapshot_report, snapshot_evidence)
        object.__setattr__(snapshot_evidence, "serials", ("toctou",))

    monkeypatch.setattr(capability_module, "_scan_privacy_snapshot", scan_then_drift)
    with pytest.raises(capability_module.PrivacyScanUnavailable, match="source drift"):
        service.probe()
    assert producer.outstanding_snapshot_count == 0


@pytest.mark.parametrize("mutated_provenance", ("forged-provenance", object()))
def test_probe_binds_privacy_evidence_provenance_into_the_exact_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    mutated_provenance: object,
) -> None:
    service, producer = trusted_probe_service(valid_report())
    real_scan = capability_module._scan_privacy_snapshot

    def scan_then_drift(
        snapshot_report: ReachyCapabilityReportV1, snapshot_evidence: object
    ) -> None:
        real_scan(snapshot_report, snapshot_evidence)
        object.__setattr__(snapshot_evidence, "provenance", mutated_provenance)

    monkeypatch.setattr(capability_module, "_scan_privacy_snapshot", scan_then_drift)

    with pytest.raises(capability_module.PrivacyScanUnavailable, match="source drift"):
        service.probe()

    assert producer.outstanding_snapshot_count == 0


def test_privacy_evidence_has_aggregate_count_and_byte_bounds() -> None:
    with pytest.raises(ValueError, match="aggregate"):
        private_scan_evidence(
            content_buffers=(
                b"a" * capability_module._MAX_PRIVACY_BINARY_VALUE_BYTES,
                b"b" * capability_module._MAX_PRIVACY_BINARY_VALUE_BYTES,
                b"c" * 16,
            )
        )

    many_values = tuple(f"private-value-{index}" for index in range(128))
    with pytest.raises(ValueError, match="aggregate"):
        private_scan_evidence(
            hostnames=many_values,
            fqdns=many_values,
            principals=many_values,
        )


def test_privacy_evidence_aggregate_limits_accept_exactly_the_limit_and_reject_plus_one() -> None:
    first_values = tuple(f"private-host-{index}" for index in range(128))
    second_values = tuple(f"private-fqdn-{index}.invalid" for index in range(128))
    exact_count = empty_private_scan_evidence(
        hostnames=first_values,
        fqdns=second_values,
    )
    assert len(exact_count.hostnames) + len(exact_count.fqdns) == (
        capability_module._MAX_PRIVACY_TOTAL_VALUES
    )
    with pytest.raises(ValueError, match="aggregate"):
        empty_private_scan_evidence(
            hostnames=first_values,
            fqdns=second_values,
            principals=("one-too-many",),
        )

    binary_limit = capability_module._MAX_PRIVACY_BINARY_VALUE_BYTES
    exact_buffers = (b"a" * binary_limit, b"b" * binary_limit)
    exact_bytes = empty_private_scan_evidence(content_buffers=exact_buffers)
    assert sum(len(value) for value in exact_bytes.content_buffers) == (
        capability_module._MAX_PRIVACY_TOTAL_BYTES
    )
    with pytest.raises(ValueError, match="aggregate"):
        empty_private_scan_evidence(content_buffers=(*exact_buffers, b"c" * 16))

    mac_addresses = tuple(
        f"02:00:00:00:{index // 256:02x}:{index % 256:02x}" for index in range(64)
    )
    exact_derived = empty_private_scan_evidence(mac_addresses=mac_addresses)
    assert 10 * len(exact_derived.mac_addresses) == capability_module._MAX_PRIVACY_DERIVED_VALUES
    with pytest.raises(ValueError, match="aggregate"):
        empty_private_scan_evidence(
            mac_addresses=mac_addresses,
            principals=("one-derived-value-too-many",),
        )


def test_bare_report_privacy_enum_cannot_authorize_a_usable_decision() -> None:
    decision = decide_capability(valid_report(report_privacy=CheckStatus.PASSED))

    assert decision.outcome is CapabilityOutcome.REJECTED
    assert decision.rejection_reasons == (RejectionReason.REPORT_PRIVACY_FAILED,)


def test_trusted_producer_requires_complete_known_value_provenance() -> None:
    evidence_type = capability_module.PrivacyScanEvidence
    with pytest.raises((TypeError, ValidationError, ValueError)):
        evidence_type(
            provenance="unknown_probe",
            hostnames=("private-reachy-host",),
        )

    values = private_scan_evidence()
    assert "private-reachy-host" not in repr(values)

    incomplete = private_scan_evidence()
    incomplete_coverage = list(incomplete.coverage)
    incomplete_coverage[0] = capability_module.PrivacyEvidenceCoverage(
        evidence_class=capability_module.PrivacyEvidenceClass.HOSTNAME,
        acquisition_source=capability_module.PrivacyAcquisitionSource.SOCKET_IDENTITY,
        status=capability_module.PrivacyCollectionStatus.PARTIAL,
    )
    object.__setattr__(incomplete, "coverage", tuple(incomplete_coverage))
    service, _ = trusted_probe_service(valid_report(), evidence=incomplete)
    with pytest.raises(capability_module.PrivacyScanUnavailable):
        service.probe()


def test_complete_privacy_snapshot_may_truthfully_have_empty_value_classes() -> None:
    evidence = private_scan_evidence(
        serials=(),
        key_material=(),
        fingerprints=(),
        content_buffers=(),
    )
    report = valid_report()
    service, _ = trusted_probe_service(report, evidence=evidence)

    probed = service.probe()

    assert decide_capability(probed).outcome is CapabilityOutcome.ACCEPTED


@pytest.mark.parametrize(
    ("report_update", "evidence_update"),
    (
        ({"sdk_version": "opaque-release"}, {"serials": ("OPAQUE-RELEASE",)}),
        ({"sdk_version": "opaque"}, {"ssids": ("ｏｐａｑｕｅ",)}),
        (
            {"sdk_version": "aabbccddeeff"},
            {"mac_addresses": ("AA:BB:CC:DD:EE:FF",)},
        ),
        (
            {"sdk_version": "3232235778"},
            {"ip_addresses": ("192.168.1.2",)},
        ),
        (
            {"sdk_version": "opaque-buffer-123"},
            {"content_buffers": (b"opaque-buffer-123",)},
        ),
    ),
)
def test_privacy_defense_scans_normalized_and_derived_private_representations(
    report_update: dict[str, object],
    evidence_update: dict[str, object],
) -> None:
    service, _ = trusted_probe_service(
        valid_report(**report_update),
        evidence=private_scan_evidence(**evidence_update),
    )

    with pytest.raises(capability_module.PrivacyScanRejected):
        service.probe()


def test_privacy_provenance_is_opaque_service_bound_and_not_caller_mintable() -> None:
    report = valid_report()
    service, _ = trusted_probe_service(report)
    probed = service.probe()

    accepted = decide_capability(probed)
    changed = valid_report(temperature_millicelsius=45_001)
    replayed = decide_capability(changed)

    assert accepted.outcome is CapabilityOutcome.ACCEPTED
    assert replayed.outcome is CapabilityOutcome.REJECTED
    assert replayed.rejection_reasons == (RejectionReason.REPORT_PRIVACY_FAILED,)
    assert "private" not in repr(probed._provenance).casefold()
    with pytest.raises(TypeError):
        capability_module.ProbedCapability()
    with pytest.raises(TypeError):
        decide_capability(
            report,
            privacy_provenance=probed._provenance,
        )


@pytest.mark.parametrize(
    "private_identifier",
    (
        "192.168.50.20",
        "2001:db8::1",
        "reachy-mini.local",
        "SERIAL-device-123",
        "owner-USERNAME-build",
    ),
)
def test_schema_rejects_private_identifiers_in_version_slots(
    private_identifier: str,
) -> None:
    schema = json.loads(render_capability_schema())
    encoded = valid_report().model_dump(mode="json")
    encoded["runtime"]["sdk_version"] = private_identifier

    assert list(Draft202012Validator(schema).iter_errors(encoded))


@pytest.mark.parametrize(
    "private_identifier",
    (
        "192.168.1.2",
        "serial-device",
        "owner-username-build",
        "reachy-mini.local",
    ),
)
def test_runtime_dependency_rejects_private_identifier_distribution(
    private_identifier: str,
) -> None:
    with pytest.raises(ValidationError):
        RuntimeDependency(
            distribution=private_identifier,
            version="1.2.3",
            artifact_sha256="4" * 64,
        )


@pytest.mark.parametrize(
    "private_identifier",
    (
        "192.168.1.2",
        "serial-device",
        "owner-username-build",
        "reachy-mini.local",
    ),
)
def test_schema_rejects_private_identifier_distribution(
    private_identifier: str,
) -> None:
    schema = json.loads(render_capability_schema())
    encoded = valid_report().model_dump(mode="json")
    encoded["runtime"]["dependencies"][0]["distribution"] = private_identifier

    assert list(Draft202012Validator(schema).iter_errors(encoded))


def test_schema_exposes_no_identifier_or_content_property() -> None:
    schema = json.loads(render_capability_schema())
    forbidden_properties = {
        "answer",
        "audio",
        "authorized_key",
        "camera_frame",
        "hostname",
        "image",
        "ip_address",
        "mac_address",
        "note",
        "pcm",
        "principal",
        "private_key",
        "provider_body",
        "public_key",
        "serial",
        "screenshot",
        "ssid",
        "transcript",
    }

    def property_names(value: object) -> set[str]:
        if isinstance(value, dict):
            names = set(value.get("properties", {}))
            return names.union(*(property_names(child) for child in value.values()))
        if isinstance(value, list):
            return set().union(*(property_names(child) for child in value))
        return set()

    assert property_names(schema).isdisjoint(forbidden_properties)
    assert "contentEncoding" not in str(schema)
    assert "contentMediaType" not in str(schema)


def test_fully_observed_report_is_accepted_for_reachy_local_input() -> None:
    decision = decide_with_privacy(valid_report())

    assert decision.outcome is CapabilityOutcome.ACCEPTED
    assert decision.input_mode is PttInputMode.REACHY_LOCAL
    assert decision.limitations == ()
    assert decision.rejection_reasons == ()
    assert decision.unknown_facts == ()


def test_proved_missing_local_input_selects_terminal_toggle_with_limitations() -> None:
    report = valid_report(
        local_capture_input=CapabilityStatus.UNAVAILABLE,
        local_stop_input=CapabilityStatus.UNAVAILABLE,
        aec=CapabilityStatus.UNAVAILABLE,
        doa=CapabilityStatus.UNAVAILABLE,
        rtc=CapabilityStatus.UNAVAILABLE,
    )

    decision = decide_with_privacy(report)

    assert decision.outcome is CapabilityOutcome.CONDITIONAL_MAC_KEY
    assert decision.input_mode is PttInputMode.CORE_TERMINAL_TOGGLE
    assert decision.limitations == (
        LimitationCode.AEC_UNAVAILABLE,
        LimitationCode.DOA_UNAVAILABLE,
        LimitationCode.LOCAL_INPUT_UNAVAILABLE,
        LimitationCode.RTC_UNQUALIFIED,
    )
    assert decision.rejection_reasons == ()
    assert decision.unknown_facts == ()


@pytest.mark.parametrize(
    "values",
    (
        {
            "outcome": CapabilityOutcome.ACCEPTED,
            "input_mode": PttInputMode.CORE_TERMINAL_TOGGLE,
        },
        {
            "outcome": CapabilityOutcome.ACCEPTED,
            "input_mode": PttInputMode.REACHY_LOCAL,
            "limitations": (LimitationCode.LOCAL_INPUT_UNAVAILABLE,),
        },
        {
            "outcome": CapabilityOutcome.ACCEPTED,
            "input_mode": PttInputMode.REACHY_LOCAL,
            "rejection_reasons": (RejectionReason.DAEMON_UNAVAILABLE,),
        },
        {
            "outcome": CapabilityOutcome.ACCEPTED,
            "input_mode": PttInputMode.REACHY_LOCAL,
            "unknown_facts": (CapabilityFact.AEC,),
        },
        {
            "outcome": CapabilityOutcome.CONDITIONAL_MAC_KEY,
            "input_mode": PttInputMode.REACHY_LOCAL,
            "limitations": (LimitationCode.LOCAL_INPUT_UNAVAILABLE,),
        },
        {
            "outcome": CapabilityOutcome.CONDITIONAL_MAC_KEY,
            "input_mode": PttInputMode.CORE_TERMINAL_TOGGLE,
        },
        {
            "outcome": CapabilityOutcome.CONDITIONAL_MAC_KEY,
            "input_mode": PttInputMode.CORE_TERMINAL_TOGGLE,
            "limitations": (LimitationCode.LOCAL_INPUT_UNAVAILABLE,),
            "rejection_reasons": (RejectionReason.DAEMON_UNAVAILABLE,),
        },
        {
            "outcome": CapabilityOutcome.CONDITIONAL_MAC_KEY,
            "input_mode": PttInputMode.CORE_TERMINAL_TOGGLE,
            "limitations": (LimitationCode.LOCAL_INPUT_UNAVAILABLE,),
            "unknown_facts": (CapabilityFact.AEC,),
        },
        {
            "outcome": CapabilityOutcome.REJECTED,
            "input_mode": PttInputMode.REACHY_LOCAL,
            "rejection_reasons": (RejectionReason.DAEMON_UNAVAILABLE,),
        },
        {
            "outcome": CapabilityOutcome.REJECTED,
            "input_mode": None,
            "limitations": (LimitationCode.AEC_UNAVAILABLE,),
            "rejection_reasons": (RejectionReason.DAEMON_UNAVAILABLE,),
        },
        {
            "outcome": CapabilityOutcome.REJECTED,
            "input_mode": None,
        },
    ),
)
def test_capability_decision_rejects_cross_field_untruths(
    values: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        CapabilityDecision.model_validate(values)


@pytest.mark.parametrize(
    "values",
    (
        {
            "outcome": CapabilityOutcome.CONDITIONAL_MAC_KEY,
            "input_mode": PttInputMode.CORE_TERMINAL_TOGGLE,
            "limitations": (
                LimitationCode.LOCAL_INPUT_UNAVAILABLE,
                LimitationCode.LOCAL_INPUT_UNAVAILABLE,
            ),
        },
        {
            "outcome": CapabilityOutcome.CONDITIONAL_MAC_KEY,
            "input_mode": PttInputMode.CORE_TERMINAL_TOGGLE,
            "limitations": (
                LimitationCode.RTC_UNQUALIFIED,
                LimitationCode.LOCAL_INPUT_UNAVAILABLE,
            ),
        },
        {
            "outcome": CapabilityOutcome.REJECTED,
            "input_mode": None,
            "rejection_reasons": (
                RejectionReason.DAEMON_UNAVAILABLE,
                RejectionReason.DAEMON_UNAVAILABLE,
            ),
        },
        {
            "outcome": CapabilityOutcome.REJECTED,
            "input_mode": None,
            "rejection_reasons": (
                RejectionReason.DAEMON_UNAVAILABLE,
                RejectionReason.NETWORK_TOPOLOGY_FAILED,
            ),
        },
        {
            "outcome": CapabilityOutcome.REJECTED,
            "input_mode": None,
            "unknown_facts": (CapabilityFact.AEC, CapabilityFact.AEC),
        },
        {
            "outcome": CapabilityOutcome.REJECTED,
            "input_mode": None,
            "unknown_facts": (CapabilityFact.DOA, CapabilityFact.AEC),
        },
    ),
)
def test_capability_decision_requires_unique_canonical_enum_order(
    values: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        CapabilityDecision.model_validate(values)


def test_decide_capability_outputs_round_trip_through_truthful_decision_model() -> None:
    reports = (
        valid_report(),
        valid_report(local_capture_input=CapabilityStatus.UNAVAILABLE),
        valid_report(network_topology=CheckStatus.FAILED),
        valid_report(aec=CapabilityStatus.UNKNOWN),
    )

    for report in reports:
        decision = decide_with_privacy(report)
        assert CapabilityDecision.model_validate(decision.model_dump()) == decision


@pytest.mark.parametrize(
    ("field", "reason"),
    (
        ("network_topology", RejectionReason.NETWORK_TOPOLOGY_FAILED),
        ("daemon_available", RejectionReason.DAEMON_UNAVAILABLE),
        ("sdk_daemon_match", RejectionReason.SDK_DAEMON_MISMATCH),
        ("interpreter_supported", RejectionReason.UNSUPPORTED_INTERPRETER),
        ("microphone_capture", RejectionReason.MEDIA_CAPTURE_FAILED),
        ("camera_frame_observed", RejectionReason.MEDIA_CAPTURE_FAILED),
        ("speaker_playback", RejectionReason.MEDIA_PLAYBACK_FAILED),
        ("playback_stop", RejectionReason.PLAYBACK_STOP_FAILED),
        ("movement_enumerated", RejectionReason.MOTION_STOP_UNAVAILABLE),
        ("motion_stop", RejectionReason.MOTION_STOP_UNAVAILABLE),
        ("app_lock", RejectionReason.CONTROLLER_DETECTION_UNAVAILABLE),
        ("controller_detection", RejectionReason.CONTROLLER_DETECTION_UNAVAILABLE),
        ("controller_collision_clear", RejectionReason.CONTROLLER_COLLISION),
        ("bind_surface", RejectionReason.UNSAFE_BIND_SURFACE),
        ("ssh_boundary", RejectionReason.SSH_BOUNDARY_FAILED),
        ("resource_limits", RejectionReason.RESOURCE_LIMIT_FAILED),
        ("report_privacy", RejectionReason.REPORT_PRIVACY_FAILED),
    ),
)
def test_each_failed_hard_check_maps_to_one_closed_rejection_reason(
    field: str,
    reason: RejectionReason,
) -> None:
    updates: dict[str, object] = {field: CheckStatus.FAILED}
    if field == "daemon_available":
        updates.update(
            daemon_evidence={
                "observation": "unobserved",
                "reason": UnobservedReason.DEPENDENCY_UNAVAILABLE,
            },
            daemon_version=None,
            daemon_artifact_sha256=None,
            sdk_daemon_match=CheckStatus.UNKNOWN,
        )
    report = valid_report(**updates)
    decision = (
        decide_capability(report) if field == "report_privacy" else decide_with_privacy(report)
    )

    assert decision.outcome is CapabilityOutcome.REJECTED
    assert decision.input_mode is None
    assert decision.limitations == ()
    assert decision.rejection_reasons == (
        (
            RejectionReason.DAEMON_UNAVAILABLE,
            RejectionReason.SDK_DAEMON_MISMATCH,
        )
        if field == "daemon_available"
        else (reason,)
    )
    assert decision.unknown_facts == ()


@pytest.mark.parametrize(
    ("field", "fact"),
    (
        ("local_capture_input", CapabilityFact.LOCAL_CAPTURE_INPUT),
        ("local_stop_input", CapabilityFact.LOCAL_STOP_INPUT),
        ("aec", CapabilityFact.AEC),
        ("doa", CapabilityFact.DOA),
        ("rtc", CapabilityFact.RTC),
    ),
)
def test_unknown_optional_fact_rejects_instead_of_becoming_a_limitation(
    field: str,
    fact: CapabilityFact,
) -> None:
    decision = decide_with_privacy(valid_report(**{field: CapabilityStatus.UNKNOWN}))

    assert decision.outcome is CapabilityOutcome.REJECTED
    assert decision.input_mode is None
    assert decision.limitations == ()
    assert decision.rejection_reasons == ()
    assert decision.unknown_facts == (fact,)


@pytest.mark.parametrize(
    "updates",
    (
        {"sdk_version": "192.168.50.20"},
        {"daemon_version": "reachy-mini.local"},
        {"python_version": "serial-device-123"},
        {"hostname": "reachy-mini"},
        {"ip_address": "192.168.50.20"},
        {"mac_address": "02:00:00:00:00:01"},
        {"ssh_principal": "owner@reachy"},
        {"ssid": "family-network"},
        {"camera_frame": b"synthetic-image"},
        {"pcm": b"synthetic-audio"},
    ),
)
def test_sanitized_report_rejects_identifier_and_media_fields_or_values(
    updates: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        valid_report(**updates)
