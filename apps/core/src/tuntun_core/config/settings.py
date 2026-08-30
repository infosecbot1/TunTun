from __future__ import annotations

from ipaddress import ip_address
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, model_validator


class FrozenSettings(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class HouseholdSettings(FrozenSettings):
    timezone: str = Field(
        default="Asia/Singapore",
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*$",
    )

    @model_validator(mode="after")
    def valid_timezone(self) -> HouseholdSettings:
        try:
            ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError as error:
            raise ValueError("timezone must name an installed IANA zone") from error
        return self


class ConversationSettings(FrozenSettings):
    active_limit: int = Field(default=1, ge=1, le=1)
    follow_up_window_seconds: int = Field(default=30, ge=1, le=600)
    idle_close_seconds: int = Field(default=60, ge=1, le=3_600)
    absolute_session_limit_minutes: int = Field(default=30, ge=1, le=1_440)

    @model_validator(mode="after")
    def ordered_windows(self) -> ConversationSettings:
        if self.follow_up_window_seconds > self.idle_close_seconds:
            raise ValueError("follow-up window must not exceed idle close")
        if self.idle_close_seconds > self.absolute_session_limit_minutes * 60:
            raise ValueError("idle close must not exceed absolute session limit")
        return self


class PrivacySettings(FrozenSettings):
    audit_default_view_days: int = Field(default=180, ge=1, le=3_650)


class NetworkSettings(FrozenSettings):
    admin_host: str = Field(default="127.0.0.1", min_length=2, max_length=64)
    admin_port: int = Field(default=8_787, ge=1, le=65_535)
    admin_lan_port: int = Field(default=8_443, ge=8_443, le=8_443)
    edge_gateway_port: int = Field(default=7_443, ge=1, le=65_535)

    @model_validator(mode="after")
    def safe_bindings(self) -> NetworkSettings:
        try:
            address = ip_address(self.admin_host)
        except ValueError as error:
            raise ValueError("admin bind must be an IP literal") from error
        if not address.is_loopback:
            raise ValueError("default admin bind must be loopback")
        if (
            len(
                {
                    self.admin_port,
                    self.admin_lan_port,
                    self.edge_gateway_port,
                }
            )
            != 3
        ):
            raise ValueError("network listener ports must be distinct")
        return self


class ProviderSettings(FrozenSettings):
    primary_model: str = Field(
        default="gpt-5.6-sol",
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$",
    )
    qwen_enabled: bool = False
    context_max_tokens: int = Field(default=8_000, ge=1_024, le=2_000_000)
    connect_timeout_ms: int = Field(default=5_000, ge=1_000, le=120_000)
    write_timeout_ms: int = Field(default=30_000, ge=1_000, le=120_000)
    read_timeout_ms: int = Field(default=120_000, ge=1_000, le=120_000)
    pool_timeout_ms: int = Field(default=5_000, ge=1_000, le=120_000)
    max_attempts: int = Field(default=2, ge=1, le=2)


class MemorySettings(FrozenSettings):
    max_items_per_turn: int = Field(default=6, ge=1, le=6)


class IdentitySettings(FrozenSettings):
    child_reenrollment_reminder_days: int = Field(
        default=180,
        ge=30,
        le=365,
    )
    child_biometric_hard_expiry_days: int = Field(
        default=365,
        ge=30,
        le=365,
    )

    @model_validator(mode="after")
    def ordered_expiry(self) -> IdentitySettings:
        if self.child_biometric_hard_expiry_days < self.child_reenrollment_reminder_days:
            raise ValueError("biometric hard expiry must follow reminder")
        return self


class AdminSettings(FrozenSettings):
    session_idle_seconds: int = Field(default=900, ge=60, le=3_600)
    session_absolute_seconds: int = Field(default=28_800, ge=300, le=86_400)
    json_body_max_bytes: int = Field(
        default=1_048_576,
        ge=1_024,
        le=16_777_216,
    )
    read_requests_per_minute: int = Field(default=120, ge=1, le=10_000)
    mutation_requests_per_minute: int = Field(default=30, ge=1, le=10_000)
    auth_requests_per_minute: int = Field(default=10, ge=1, le=10_000)
    trust_proxy_headers: bool = False

    @model_validator(mode="after")
    def safe_admin_policy(self) -> AdminSettings:
        if self.session_idle_seconds > self.session_absolute_seconds:
            raise ValueError("admin idle expiry must not exceed absolute expiry")
        if self.trust_proxy_headers:
            raise ValueError("proxy headers are disabled in Phase 1")
        return self


class ObservabilitySettings(FrozenSettings):
    telemetry_enabled: bool = False
    cloud_tracing_enabled: bool = False
    provider_body_logging: bool = False

    @model_validator(mode="after")
    def local_only(self) -> ObservabilitySettings:
        if any(
            (
                self.telemetry_enabled,
                self.cloud_tracing_enabled,
                self.provider_body_logging,
            )
        ):
            raise ValueError("Phase 1 observability privacy switches stay disabled")
        return self


class BudgetSettings(FrozenSettings):
    soft_limit_micros_sgd: int = Field(
        default=100_000_000,
        ge=0,
        le=10_000_000_000,
    )
    hard_limit_micros_sgd: int = Field(
        default=150_000_000,
        ge=0,
        le=10_000_000_000,
    )

    @model_validator(mode="after")
    def ordered_limits(self) -> BudgetSettings:
        if self.hard_limit_micros_sgd < self.soft_limit_micros_sgd:
            raise ValueError("hard limit must be at least soft limit")
        return self


class Settings(FrozenSettings):
    household: HouseholdSettings = Field(default_factory=HouseholdSettings)
    conversation: ConversationSettings = Field(default_factory=ConversationSettings)
    privacy: PrivacySettings = Field(default_factory=PrivacySettings)
    network: NetworkSettings = Field(default_factory=NetworkSettings)
    providers: ProviderSettings = Field(default_factory=ProviderSettings)
    memory: MemorySettings = Field(default_factory=MemorySettings)
    identity: IdentitySettings = Field(default_factory=IdentitySettings)
    admin: AdminSettings = Field(default_factory=AdminSettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)
    budget: BudgetSettings = Field(default_factory=BudgetSettings)
