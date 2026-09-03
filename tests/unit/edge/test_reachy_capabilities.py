from __future__ import annotations

import sys
from typing import cast

import pytest
from pydantic import ValidationError
from tuntun_contracts.base import ContractModel, canonical_bytes
from tuntun_edge.config import (
    EdgeConfig,
    ReachyHardwareConfig,
    ReachyNetworkConfigV1,
    load_edge_config,
)
from tuntun_edge.reachy import probe as exported_probe
from tuntun_edge.reachy.probe import (
    REACHY_SDK_DECLARED_NATIVE_AUDIO_FORMAT,
    TUNTUN_TRANSPORT_AUDIO_FORMAT,
    CapabilityReport,
    ProbeSource,
    ReachyCapabilityEvidenceV1,
    ReachyCapabilityEvidenceV2,
    ReachyCapabilityReportV1,
    ReachyHardwareNotAllowedError,
    ReachyMediaFacts,
    ReachyRtcFacts,
    probe,
    probe_reachy_capabilities,
    probe_reachy_hardware_capabilities,
)

PRIVATE_TOKENS = (
    "kitchen-reachy",
    "192.168.1.42",
    "aa:bb:cc:dd:ee:ff",
    "reachy-serial",
    "sanjay",
    "/Users/sanjay",
    "HomeWifi",
    "ssh-ed25519",
    "BEGIN OPENSSH PRIVATE KEY",
    "transcript",
    "RIFF",
    "operator note",
)


class RawFakeSource:
    sdk_version = "1.2.3"
    daemon_version = "4.5.6"
    native_capture_media = ReachyMediaFacts(
        sample_format="float32_le",
        sample_rate_hz=16000,
        channels=2,
        interleaved=True,
        channel_layout="stereo",
        evidence_basis="physical_observed",
    )
    native_playback_media = ReachyMediaFacts(
        sample_format="float32_le",
        sample_rate_hz=16000,
        channels=2,
        interleaved=True,
        channel_layout="stereo",
        evidence_basis="physical_observed",
    )
    aec_available = True
    doa_available = False
    daemon_ports: tuple[int, ...] = (8000, 8001)
    secure_key_storage_available = True
    managed_app_lock_available = True
    competing_controller_detectable = True
    stop_during_playback_tested = True
    rtc_available = True
    rtc_cold_boot_retains_utc = True
    rtc_max_drift_seconds_30d: float | None = 5.0


class HostileProvenanceSource(RawFakeSource):
    source = "synthetic"
    probe_version = "999.999.999"


def _synthetic_report_dict() -> dict[str, object]:
    return probe_reachy_capabilities(mode="synthetic").model_dump()


def _legacy_v1_report_dict() -> dict[str, object]:
    return {
        "schema_version": "tuntun.reachy-capability-report.v1",
        "source": "hardware",
        "probe_version": "0.1.0",
        "sdk_version": "1.2.3",
        "daemon_version": "4.5.6",
        "input_rate_hz": 16000,
        "input_channels": 1,
        "output_rate_hz": 16000,
        "output_channels": 1,
        "aec_available": True,
        "doa_available": False,
        "daemon_ports": (8000, 8001),
        "secure_key_storage_available": True,
        "managed_app_lock_available": True,
        "competing_controller_detectable": True,
        "stop_during_playback_tested": True,
        "rtc_available": True,
        "rtc_cold_boot_retains_utc": True,
        "rtc_max_drift_seconds_30d": 5.0,
        "rtc_qualified": True,
    }


def _rtc_fact_dict() -> dict[str, object]:
    return {
        "rtc_available": True,
        "unplugged_cold_boot_retained": True,
        "real_drift_measurement_days": 30,
        "max_observed_drift_seconds": 5.0,
        "rtc_qualified": True,
    }


def test_legacy_v1_capability_report_is_explicitly_not_the_current_schema() -> None:
    legacy = ReachyCapabilityEvidenceV1.model_validate(_legacy_v1_report_dict())

    assert legacy.schema_version == "tuntun.reachy-capability-report.v1"
    assert ReachyCapabilityEvidenceV1 is ReachyCapabilityReportV1
    assert ReachyCapabilityEvidenceV2 is CapabilityReport
    with pytest.raises(ValidationError):
        CapabilityReport.model_validate(_legacy_v1_report_dict())


def test_probe_owns_hardware_provenance_and_reads_exact_raw_fact_names() -> None:
    source: ProbeSource = RawFakeSource()
    report = probe(source)

    assert exported_probe is probe
    assert isinstance(report, ContractModel)
    assert type(report) is CapabilityReport
    assert ReachyCapabilityEvidenceV2 is CapabilityReport
    assert report.model_dump() == {
        "schema_version": "tuntun.reachy-capability-report.v2",
        "source": "hardware",
        "probe_version": "0.1.0",
        "sdk_version": "1.2.3",
        "daemon_version": "4.5.6",
        "native_capture_media": {
            "sample_format": "float32_le",
            "sample_rate_hz": 16000,
            "channels": 2,
            "interleaved": True,
            "channel_layout": "stereo",
            "evidence_basis": "physical_observed",
        },
        "native_playback_media": {
            "sample_format": "float32_le",
            "sample_rate_hz": 16000,
            "channels": 2,
            "interleaved": True,
            "channel_layout": "stereo",
            "evidence_basis": "physical_observed",
        },
        "tuntun_transport_media": {
            "sample_format": "s16le",
            "sample_rate_hz": 16000,
            "channels": 1,
            "interleaved": False,
            "channel_layout": "mono",
        },
        "aec_available": True,
        "doa_available": False,
        "daemon_ports": (8000, 8001),
        "secure_key_storage_available": True,
        "managed_app_lock_available": True,
        "competing_controller_detectable": True,
        "stop_during_playback_tested": True,
        "rtc_available": True,
        "rtc_cold_boot_retains_utc": True,
        "rtc_max_drift_seconds_30d": 5.0,
        "rtc_qualified": True,
    }


def test_probe_ignores_bogus_raw_source_provenance() -> None:
    report = probe(HostileProvenanceSource())

    assert report.source == "hardware"
    assert report.probe_version == "0.1.0"


def test_synthetic_capability_report_is_strict_contract_and_sanitized() -> None:
    report = probe_reachy_capabilities(mode="synthetic")

    assert isinstance(report, ContractModel)
    assert isinstance(report, CapabilityReport)
    assert ReachyCapabilityEvidenceV2 is CapabilityReport
    assert report.schema_version == "tuntun.reachy-capability-report.v2"
    assert report.source == "synthetic"
    assert report.probe_version == "0.1.0"
    assert report.sdk_version == "0.0.0"
    assert report.daemon_version == "0.0.0"
    assert report.native_capture_media == ReachyMediaFacts(
        sample_format="float32_le",
        sample_rate_hz=16000,
        channels=2,
        interleaved=True,
        channel_layout="stereo",
        evidence_basis="sdk_declared",
    )
    assert report.native_playback_media == ReachyMediaFacts(
        sample_format="float32_le",
        sample_rate_hz=16000,
        channels=2,
        interleaved=True,
        channel_layout="stereo",
        evidence_basis="sdk_declared",
    )
    assert report.tuntun_transport_media.model_dump() == {
        "sample_format": "s16le",
        "sample_rate_hz": 16000,
        "channels": 1,
        "interleaved": False,
        "channel_layout": "mono",
    }
    assert report.native_capture_media.model_dump(exclude={"evidence_basis"}) == (
        REACHY_SDK_DECLARED_NATIVE_AUDIO_FORMAT.model_dump()
    )
    assert report.native_playback_media.model_dump(exclude={"evidence_basis"}) == (
        REACHY_SDK_DECLARED_NATIVE_AUDIO_FORMAT.model_dump()
    )
    assert report.tuntun_transport_media.model_dump() == TUNTUN_TRANSPORT_AUDIO_FORMAT.model_dump()
    assert "input_rate_hz" not in report.model_dump()
    assert "input_channels" not in report.model_dump()
    assert "output_rate_hz" not in report.model_dump()
    assert "output_channels" not in report.model_dump()
    assert report.aec_available is False
    assert report.doa_available is False
    assert report.daemon_ports == (8000, 8001)
    assert 22 not in report.daemon_ports
    assert report.secure_key_storage_available is False
    assert report.managed_app_lock_available is False
    assert report.competing_controller_detectable is False
    assert report.stop_during_playback_tested is False
    assert report.rtc_available is False
    assert report.rtc_cold_boot_retains_utc is False
    assert report.rtc_max_drift_seconds_30d is None
    assert report.rtc_qualified is False

    rendered = canonical_bytes(report).decode("ascii")
    assert "physical_observed" not in rendered
    for token in PRIVATE_TOKENS:
        assert token not in rendered

    raw = report.model_dump()
    with pytest.raises(ValidationError):
        CapabilityReport.model_validate({**raw, **_legacy_v1_report_dict()})
    with pytest.raises(ValidationError):
        CapabilityReport.model_validate({**raw, "hostname": "kitchen-reachy"})
    with pytest.raises(ValidationError):
        CapabilityReport.model_validate({**raw, "operator_notes": "operator note"})
    with pytest.raises(ValidationError):
        CapabilityReport.model_validate(
            {
                **raw,
                "native_capture_media": {
                    **report.native_capture_media.model_dump(),
                    "operator_notes": "operator note",
                },
            }
        )
    with pytest.raises(ValidationError):
        CapabilityReport.model_validate(
            {
                **raw,
                "native_capture_media": {
                    **report.native_capture_media.model_dump(),
                    "evidence_basis": b"sdk_declared",
                },
            }
        )
    with pytest.raises(ValidationError):
        CapabilityReport.model_validate(
            {
                **raw,
                "native_capture_media": {
                    **report.native_capture_media.model_dump(),
                    "evidence_basis": "physical_observed",
                },
            }
        )


@pytest.mark.parametrize(
    "field",
    (
        "schema_version",
        "source",
        "probe_version",
        "sdk_version",
        "daemon_version",
        "native_capture_media",
        "native_playback_media",
        "tuntun_transport_media",
        "aec_available",
        "doa_available",
        "daemon_ports",
        "secure_key_storage_available",
        "managed_app_lock_available",
        "competing_controller_detectable",
        "stop_during_playback_tested",
        "rtc_available",
        "rtc_cold_boot_retains_utc",
        "rtc_max_drift_seconds_30d",
        "rtc_qualified",
    ),
)
def test_capability_report_rejects_missing_required_fields(field: str) -> None:
    raw = _synthetic_report_dict()
    raw.pop(field)

    with pytest.raises(ValidationError):
        CapabilityReport.model_validate(raw)


@pytest.mark.parametrize(
    "version",
    ("1.2", "1.2.3.dev0", "1.2.3-alpha", "01.2.3", "latest", ""),
)
def test_capability_report_rejects_non_stable_semver(version: str) -> None:
    raw = _synthetic_report_dict()
    raw["sdk_version"] = version

    with pytest.raises(ValidationError):
        CapabilityReport.model_validate(raw)


@pytest.mark.parametrize("field", ("sdk_version", "daemon_version"))
def test_capability_report_rejects_overlong_stable_semver(field: str) -> None:
    raw = _synthetic_report_dict()
    raw[field] = f"1.2.{'3' * 64}"

    with pytest.raises(ValidationError):
        CapabilityReport.model_validate(raw)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        (
            "native_capture_media",
            {
                **cast(
                    dict[str, object],
                    _synthetic_report_dict()["native_capture_media"],
                ),
                "channels": 1,
            },
        ),
        (
            "native_playback_media",
            {
                **cast(
                    dict[str, object],
                    _synthetic_report_dict()["native_playback_media"],
                ),
                "interleaved": False,
            },
        ),
        (
            "tuntun_transport_media",
            {
                **cast(
                    dict[str, object],
                    _synthetic_report_dict()["tuntun_transport_media"],
                ),
                "channels": 2,
            },
        ),
    ),
)
def test_capability_report_rejects_unsupported_or_non_strict_media_facts(
    field: str,
    value: object,
) -> None:
    raw = _synthetic_report_dict()
    raw[field] = value

    with pytest.raises(ValidationError):
        CapabilityReport.model_validate(raw)


def test_unknown_native_media_descriptor_carries_no_contradictory_format_claims() -> None:
    unknown = ReachyMediaFacts(evidence_basis="unknown")

    assert unknown.model_dump() == {
        "sample_format": None,
        "sample_rate_hz": None,
        "channels": None,
        "interleaved": None,
        "channel_layout": None,
        "evidence_basis": "unknown",
    }
    with pytest.raises(ValidationError):
        ReachyMediaFacts(
            sample_format="float32_le",
            sample_rate_hz=16000,
            channels=2,
            interleaved=True,
            channel_layout="stereo",
            evidence_basis="unknown",
        )


@pytest.mark.parametrize(
    "ports",
    (
        (),
        (22, 22),
        (8080, 22),
        tuple(range(1, 18)),
        (True,),
        (0,),
        (65536,),
    ),
)
def test_capability_report_rejects_empty_unsorted_duplicate_or_non_strict_ports(
    ports: tuple[object, ...],
) -> None:
    raw = _synthetic_report_dict()
    raw["daemon_ports"] = ports

    with pytest.raises(ValidationError):
        CapabilityReport.model_validate(raw)


@pytest.mark.parametrize(
    "updates",
    (
        {"rtc_available": False, "rtc_qualified": True},
        {"rtc_cold_boot_retains_utc": False, "rtc_qualified": True},
        {"rtc_max_drift_seconds_30d": None, "rtc_qualified": True},
        {"rtc_max_drift_seconds_30d": 5.1, "rtc_qualified": True},
        {"rtc_qualified": False},
    ),
)
def test_capability_report_requires_rtc_qualification_to_match_facts(
    updates: dict[str, object],
) -> None:
    raw = probe(RawFakeSource()).model_dump()
    raw.update(updates)

    with pytest.raises(ValidationError):
        CapabilityReport.model_validate(raw)


@pytest.mark.parametrize(
    "updates",
    (
        {
            "rtc_available": False,
            "rtc_cold_boot_retains_utc": True,
            "rtc_max_drift_seconds_30d": None,
            "rtc_qualified": False,
        },
        {
            "rtc_available": False,
            "rtc_cold_boot_retains_utc": False,
            "rtc_max_drift_seconds_30d": 5.0,
            "rtc_qualified": False,
        },
        {
            "rtc_available": True,
            "rtc_cold_boot_retains_utc": False,
            "rtc_max_drift_seconds_30d": 5.0,
            "rtc_qualified": False,
        },
    ),
)
def test_capability_report_rejects_impossible_rtc_fact_combinations(
    updates: dict[str, object],
) -> None:
    raw = _synthetic_report_dict()
    raw.update(updates)

    with pytest.raises(ValidationError):
        CapabilityReport.model_validate(raw)


def test_capability_report_accepts_exact_safe_rtc_qualification() -> None:
    report = CapabilityReport.model_validate(probe(RawFakeSource()).model_dump())

    assert report.rtc_available is True
    assert report.rtc_cold_boot_retains_utc is True
    assert report.rtc_max_drift_seconds_30d == 5.0
    assert report.rtc_qualified is True


@pytest.mark.parametrize(
    "updates",
    (
        {
            "rtc_available": False,
            "unplugged_cold_boot_retained": True,
            "real_drift_measurement_days": 0,
            "max_observed_drift_seconds": None,
            "rtc_qualified": False,
        },
        {
            "rtc_available": False,
            "unplugged_cold_boot_retained": False,
            "real_drift_measurement_days": 30,
            "max_observed_drift_seconds": 5.0,
            "rtc_qualified": False,
        },
        {
            "rtc_available": True,
            "unplugged_cold_boot_retained": False,
            "real_drift_measurement_days": 30,
            "max_observed_drift_seconds": 5.0,
            "rtc_qualified": False,
        },
    ),
)
def test_reachy_rtc_facts_reject_impossible_fact_combinations(
    updates: dict[str, object],
) -> None:
    raw = _rtc_fact_dict()
    raw.update(updates)

    with pytest.raises(ValidationError):
        ReachyRtcFacts.model_validate(raw)


def test_reachy_rtc_facts_requires_qualification_to_match_strict_facts() -> None:
    raw = _rtc_fact_dict()
    raw["rtc_qualified"] = False

    with pytest.raises(ValidationError):
        ReachyRtcFacts.model_validate(raw)


def test_hardware_probe_requires_explicit_opt_in_before_sdk_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ImportBlocker:
        def find_spec(self, fullname: str, path: object, target: object | None = None) -> object:
            if fullname.startswith("reachy"):
                raise AssertionError("Reachy SDK import was attempted before hardware opt-in")
            return None

    monkeypatch.setattr(sys, "meta_path", [ImportBlocker(), *sys.meta_path])

    with pytest.raises(ReachyHardwareNotAllowedError, match="TUNTUN_ALLOW_REACHY_HARDWARE"):
        probe_reachy_hardware_capabilities(environ={})


def test_edge_config_parses_hardware_gate_without_importing_reachy_sdk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ImportBlocker:
        def find_spec(self, fullname: str, path: object, target: object | None = None) -> object:
            if fullname.startswith("reachy"):
                raise AssertionError("Reachy SDK import should be lazy")
            return None

    monkeypatch.setattr(sys, "meta_path", [ImportBlocker(), *sys.meta_path])

    defaults = load_edge_config({})
    assert defaults == EdgeConfig(
        media_backend="local",
        gateway_port=7443,
        telemetry_enabled=False,
        controller_violation_fails_safe=True,
        reachy=ReachyHardwareConfig(allow_hardware=False),
    )
    assert load_edge_config({"TUNTUN_ALLOW_REACHY_HARDWARE": "1"}).reachy == (
        ReachyHardwareConfig(allow_hardware=True)
    )

    settings = load_edge_config({"TUNTUN_ALLOW_REACHY_HARDWARE": "0"})
    assert isinstance(settings, EdgeConfig)
    assert settings.reachy.allow_hardware is False


@pytest.mark.parametrize(
    "environ",
    (
        {"TUNTUN_ALLOW_REACHY_HARDWARE": "true"},
        {"TUNTUN_ALLOW_REACHY_HARDWARE": "1\nTUNTUN_ALLOW_LIVE_CLOUD=1"},
        {"TUNTUN_ALLOW_REACHY_HARDWARE": " 1"},
    ),
)
def test_edge_config_rejects_injected_hardware_gate_strings(environ: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="TUNTUN_ALLOW_REACHY_HARDWARE"):
        load_edge_config(environ)


@pytest.mark.parametrize(
    "kwargs",
    (
        {"media_backend": "cloud"},
        {"gateway_port": 7444},
        {"telemetry_enabled": True},
        {"controller_violation_fails_safe": False},
    ),
)
def test_edge_config_rejects_unsafe_alternate_defaults(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        EdgeConfig.model_validate(kwargs)


def test_reachy_network_config_serializes_direct_safe_interface_key() -> None:
    config = ReachyNetworkConfigV1(
        schema_version="tuntun.reachy-network-config.v1",
        generation=1,
        reachy_ingress_interface="en0",
    )

    assert isinstance(config, ContractModel)
    assert config.reachy_ingress_interface == "en0"
    assert config.model_dump() == {
        "schema_version": "tuntun.reachy-network-config.v1",
        "generation": 1,
        "reachy_ingress_interface": "en0",
    }

    with pytest.raises(ValidationError):
        ReachyNetworkConfigV1.model_validate({**config.model_dump(), "peer_ip": "192.168.1.42"})
    with pytest.raises(ValidationError):
        ReachyNetworkConfigV1.model_validate({**config.model_dump(), "hostname": "kitchen-reachy"})


@pytest.mark.parametrize(
    "name",
    ("", "en 0", "en0;rm", "../../en0", "a" * 16, "$en0", "en0:1"),
)
def test_reachy_ingress_interface_rejects_injection_strings(name: str) -> None:
    raw = {
        "schema_version": "tuntun.reachy-network-config.v1",
        "generation": 1,
        "reachy_ingress_interface": name,
    }

    with pytest.raises(ValidationError):
        ReachyNetworkConfigV1.model_validate(raw)
