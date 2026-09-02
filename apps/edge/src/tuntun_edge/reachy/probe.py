from __future__ import annotations

import importlib
from collections.abc import Mapping
from typing import Annotated, Any, Literal, Protocol, Self

from pydantic import Field, field_validator, model_validator
from tuntun_contracts.base import ContractModel

from tuntun_edge.config import load_edge_config

_STABLE_SEMVER_PATTERN = r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$"
_STABLE_SEMVER_MAX_LENGTH = 32
_PROBE_VERSION = "0.1.0"
_SYNTHETIC_VERSION = "0.0.0"
_REACHY_HARDWARE_FLAG = "TUNTUN_ALLOW_REACHY_HARDWARE"

StableSemver = Annotated[
    str,
    Field(pattern=_STABLE_SEMVER_PATTERN, max_length=_STABLE_SEMVER_MAX_LENGTH),
]
NetworkPort = Annotated[int, Field(ge=1, le=65535)]


class ReachyHardwareNotAllowedError(PermissionError):
    pass


class ReachyHardwareProbeUnavailableError(RuntimeError):
    pass


class ReachyMediaFacts(ContractModel):
    sample_format: Literal["s16le"]
    sample_rate_hz: Literal[16000]
    channels: Literal[1]
    channel_layout: Literal["mono"]


class ReachyRtcFacts(ContractModel):
    rtc_available: bool
    unplugged_cold_boot_retained: bool
    real_drift_measurement_days: Annotated[int, Field(ge=0, le=30)]
    max_observed_drift_seconds: Annotated[float, Field(ge=0, le=86_400)] | None
    rtc_qualified: bool

    @model_validator(mode="after")
    def require_consistent_rtc_facts(self) -> Self:
        has_drift_evidence = (
            self.real_drift_measurement_days > 0 or self.max_observed_drift_seconds is not None
        )
        if not self.rtc_available and self.unplugged_cold_boot_retained:
            raise ValueError("RTC cold-boot retention requires RTC availability")
        if has_drift_evidence and (
            not self.rtc_available or not self.unplugged_cold_boot_retained
        ):
            raise ValueError("RTC drift evidence requires available retained RTC")
        if self.real_drift_measurement_days == 0 and self.max_observed_drift_seconds is not None:
            raise ValueError("RTC drift requires a real measurement interval")
        if self.real_drift_measurement_days > 0 and self.max_observed_drift_seconds is None:
            raise ValueError("RTC drift seconds are required for measured intervals")
        computed = (
            self.rtc_available
            and self.unplugged_cold_boot_retained
            and self.real_drift_measurement_days == 30
            and self.max_observed_drift_seconds is not None
            and self.max_observed_drift_seconds <= 5.0
        )
        if self.rtc_qualified is not computed:
            raise ValueError("RTC qualification must match retained 30-day drift facts")
        return self


class CapabilityReport(ContractModel):
    schema_version: Literal["tuntun.reachy-capability-report.v1"]
    source: Literal["synthetic", "hardware"]
    probe_version: StableSemver
    sdk_version: StableSemver
    daemon_version: StableSemver
    input_rate_hz: Literal[16000]
    input_channels: Literal[1]
    output_rate_hz: Literal[16000]
    output_channels: Literal[1]
    aec_available: bool
    doa_available: bool
    daemon_ports: Annotated[tuple[NetworkPort, ...], Field(min_length=1, max_length=16)]
    secure_key_storage_available: bool
    managed_app_lock_available: bool
    competing_controller_detectable: bool
    stop_during_playback_tested: bool
    rtc_available: bool
    rtc_cold_boot_retains_utc: bool
    rtc_max_drift_seconds_30d: Annotated[float, Field(ge=0, le=86_400)] | None
    rtc_qualified: bool

    @property
    def reachy_sdk_version(self) -> str:
        return self.sdk_version

    @property
    def microphone(self) -> ReachyMediaFacts:
        return ReachyMediaFacts(
            sample_format="s16le",
            sample_rate_hz=self.input_rate_hz,
            channels=self.input_channels,
            channel_layout="mono",
        )

    @property
    def speaker(self) -> ReachyMediaFacts:
        return ReachyMediaFacts(
            sample_format="s16le",
            sample_rate_hz=self.output_rate_hz,
            channels=self.output_channels,
            channel_layout="mono",
        )

    @property
    def observed_ports(self) -> tuple[int, ...]:
        return self.daemon_ports

    @property
    def rtc(self) -> ReachyRtcFacts:
        return ReachyRtcFacts(
            rtc_available=self.rtc_available,
            unplugged_cold_boot_retained=self.rtc_cold_boot_retains_utc,
            real_drift_measurement_days=30 if self.rtc_max_drift_seconds_30d is not None else 0,
            max_observed_drift_seconds=self.rtc_max_drift_seconds_30d,
            rtc_qualified=self.rtc_qualified,
        )

    @field_validator(
        "input_rate_hz", "input_channels", "output_rate_hz", "output_channels", mode="before"
    )
    @classmethod
    def require_strict_media_integer(cls, value: int) -> int:
        if type(value) is not int:
            raise ValueError("media rate and channel facts must be strict integers")
        return value

    @field_validator("daemon_ports")
    @classmethod
    def require_unique_sorted_ports(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if any(type(port) is not int for port in value):
            raise ValueError("daemon ports must be strict integers")
        if tuple(sorted(value)) != value:
            raise ValueError("daemon ports must be sorted")
        if len(set(value)) != len(value):
            raise ValueError("daemon ports must be unique")
        return value

    @model_validator(mode="after")
    def require_consistent_rtc_facts(self) -> Self:
        if not self.rtc_available and self.rtc_cold_boot_retains_utc:
            raise ValueError("RTC cold-boot retention requires RTC availability")
        if self.rtc_max_drift_seconds_30d is not None and (
            not self.rtc_available or not self.rtc_cold_boot_retains_utc
        ):
            raise ValueError("RTC drift evidence requires available retained RTC")
        computed = (
            self.rtc_available
            and self.rtc_cold_boot_retains_utc
            and self.rtc_max_drift_seconds_30d is not None
            and self.rtc_max_drift_seconds_30d <= 5.0
        )
        if self.rtc_qualified is not computed:
            raise ValueError("RTC qualification must match explicit 30-day facts")
        return self


class ProbeSource(Protocol):
    sdk_version: str
    daemon_version: str
    input_rate_hz: int
    input_channels: int
    output_rate_hz: int
    output_channels: int
    aec_available: bool
    doa_available: bool
    daemon_ports: tuple[int, ...]
    secure_key_storage_available: bool
    managed_app_lock_available: bool
    competing_controller_detectable: bool
    stop_during_playback_tested: bool
    rtc_available: bool
    rtc_cold_boot_retains_utc: bool
    rtc_max_drift_seconds_30d: float | None


ReachyCapabilityEvidenceV1 = CapabilityReport


def _build_capability_report(
    source: ProbeSource,
    *,
    report_source: Literal["synthetic", "hardware"],
) -> CapabilityReport:
    rtc_qualified = (
        source.rtc_available
        and source.rtc_cold_boot_retains_utc
        and source.rtc_max_drift_seconds_30d is not None
        and source.rtc_max_drift_seconds_30d <= 5.0
    )
    return CapabilityReport.model_validate(
        {
            "schema_version": "tuntun.reachy-capability-report.v1",
            "source": report_source,
            "probe_version": _PROBE_VERSION,
            "sdk_version": source.sdk_version,
            "daemon_version": source.daemon_version,
            "input_rate_hz": source.input_rate_hz,
            "input_channels": source.input_channels,
            "output_rate_hz": source.output_rate_hz,
            "output_channels": source.output_channels,
            "aec_available": source.aec_available,
            "doa_available": source.doa_available,
            "daemon_ports": source.daemon_ports,
            "secure_key_storage_available": source.secure_key_storage_available,
            "managed_app_lock_available": source.managed_app_lock_available,
            "competing_controller_detectable": source.competing_controller_detectable,
            "stop_during_playback_tested": source.stop_during_playback_tested,
            "rtc_available": source.rtc_available,
            "rtc_cold_boot_retains_utc": source.rtc_cold_boot_retains_utc,
            "rtc_max_drift_seconds_30d": source.rtc_max_drift_seconds_30d,
            "rtc_qualified": rtc_qualified,
        }
    )


def probe(source: ProbeSource) -> CapabilityReport:
    return _build_capability_report(source, report_source="hardware")


class _SyntheticProbeSource:
    sdk_version = _SYNTHETIC_VERSION
    daemon_version = _SYNTHETIC_VERSION
    input_rate_hz = 16000
    input_channels = 1
    output_rate_hz = 16000
    output_channels = 1
    aec_available = False
    doa_available = False
    daemon_ports: tuple[int, ...] = (8000, 8001)
    secure_key_storage_available = False
    managed_app_lock_available = False
    competing_controller_detectable = False
    stop_during_playback_tested = False
    rtc_available = False
    rtc_cold_boot_retains_utc = False
    rtc_max_drift_seconds_30d: float | None = None


def synthetic_reachy_capabilities() -> CapabilityReport:
    return _build_capability_report(_SyntheticProbeSource(), report_source="synthetic")


def probe_reachy_capabilities(
    *,
    mode: Literal["synthetic", "hardware"] = "synthetic",
    environ: Mapping[str, str] | None = None,
) -> CapabilityReport:
    if mode == "synthetic":
        return synthetic_reachy_capabilities()
    if mode == "hardware":
        return probe_reachy_hardware_capabilities(environ=environ)
    raise ValueError("unsupported Reachy capability probe mode")


def _load_reachy_sdk() -> Any:
    try:
        return importlib.import_module("reachy_mini")
    except ImportError as error:
        raise ReachyHardwareProbeUnavailableError("Reachy hardware SDK is unavailable") from error


def probe_reachy_hardware_capabilities(
    *,
    environ: Mapping[str, str] | None = None,
) -> CapabilityReport:
    if not load_edge_config(environ).reachy.allow_hardware:
        raise ReachyHardwareNotAllowedError(
            f"{_REACHY_HARDWARE_FLAG}=1 is required for Reachy hardware probing"
        )
    _load_reachy_sdk()
    raise ReachyHardwareProbeUnavailableError(
        "Reachy hardware capability probing needs the future supervised physical procedure"
    )
