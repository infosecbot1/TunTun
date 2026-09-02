# packages/contracts/src/tuntun_contracts/speech.py
from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Literal, Self
from unicodedata import normalize
from uuid import UUID

from pydantic import Field, ModelWrapValidatorHandler, field_validator, model_validator

from .base import Commitment, ContractModel
from .provider import RouteAuthorization


class AudioFormat(ContractModel):
    sample_format: Literal["float32_le", "s16le"]
    sample_rate_hz: Annotated[int, Field(ge=8_000, le=96_000)]
    channels: Annotated[int, Field(ge=1, le=4)]
    interleaved: bool
    channel_layout: Literal["mono", "stereo", "reachy_native"]


class AuthorizedTranscriptionRequest(ContractModel):
    request_id: UUID
    turn_id: UUID
    audio_format: AudioFormat
    audio_commitment: Commitment
    audio_bytes: Annotated[int, Field(ge=1, le=8_388_608)]
    duration_ms: Annotated[int, Field(ge=1, le=90_000)]
    language_hints: Annotated[
        tuple[Literal["en", "hi"], ...],
        Field(min_length=1, max_length=2),
    ]
    route: RouteAuthorization

    @field_validator("language_hints")
    @classmethod
    def unique_language_hints(
        cls,
        value: tuple[Literal["en", "hi"], ...],
    ) -> tuple[Literal["en", "hi"], ...]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate language hint")
        return value

    @model_validator(mode="after")
    def exact_transcription_route(self) -> Self:
        if (
            self.request_id != self.route.request_id
            or self.turn_id != self.route.turn_id
            or self.route.purpose != "cloud_stt"
            or self.audio_commitment != self.route.request_commitment
        ):
            raise ValueError("transcription request route mismatch")
        return self


class TranscriptResult(ContractModel):
    request_id: UUID
    text: Annotated[str, Field(min_length=1, max_length=32_000)]
    language: Literal["en", "hi", "hinglish", "unknown"]
    duration_ms: Annotated[int, Field(ge=0, le=90_000)]


class OfflineSynthesisRequest(ContractModel):
    request_id: UUID
    turn_id: UUID
    text: Annotated[str, Field(min_length=1, max_length=4_096)]
    language: Literal["en", "hi", "hinglish"]

    @model_validator(mode="wrap")
    @classmethod
    def raw_text_must_be_nfc(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if isinstance(value, Mapping):
            text = value.get("text")
            if type(text) is str and text != normalize("NFC", text):
                raise ValueError("offline_tts_text_must_be_bounded_nfc")
        return handler(value)

    @field_validator("text")
    @classmethod
    def bounded_nfc_text(cls, value: str) -> str:
        if value != normalize("NFC", value) or not 1 <= len(value) <= 4_096:
            raise ValueError("offline_tts_text_must_be_bounded_nfc")
        return value


class AuthorizedSynthesisRequest(ContractModel):
    request_id: UUID
    turn_id: UUID
    text: Annotated[str, Field(min_length=1, max_length=4_096)]
    text_commitment: Commitment
    segment_index: Annotated[int, Field(ge=0, le=255)]
    segment_count: Annotated[int, Field(ge=1, le=256)]
    language: Literal["en", "hi", "hinglish"]
    dlp_receipt_id: UUID
    route: RouteAuthorization

    @model_validator(mode="wrap")
    @classmethod
    def raw_text_must_be_nfc(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if isinstance(value, Mapping):
            text = value.get("text")
            if type(text) is str and text != normalize("NFC", text):
                raise ValueError("tts_text_must_be_bounded_nfc")
        return handler(value)

    @field_validator("text")
    @classmethod
    def bounded_nfc_text(cls, value: str) -> str:
        if value != normalize("NFC", value) or not 1 <= len(value) <= 4_096:
            raise ValueError("tts_text_must_be_bounded_nfc")
        return value

    @model_validator(mode="after")
    def exact_synthesis_route(self) -> Self:
        if (
            self.request_id != self.route.request_id
            or self.turn_id != self.route.turn_id
            or self.route.purpose != "cloud_tts"
            or self.text_commitment != self.route.request_commitment
            or self.segment_index >= self.segment_count
        ):
            raise ValueError("synthesis request route mismatch")
        return self


class SpeechChunk(ContractModel):
    request_id: UUID
    sequence: Annotated[int, Field(ge=0)]
    pcm: Annotated[bytes, Field(max_length=65_536)]
    final: bool
