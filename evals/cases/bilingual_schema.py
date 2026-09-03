from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field, field_validator, model_validator
from tuntun_contracts.base import ContractModel
from tuntun_contracts.identity import PersonaProjection

TopicTerm = Annotated[str, Field(min_length=1, max_length=64)]
InputClass = Literal["english", "hindi_devanagari", "hindi_romanized", "mixed"]
ReplyMode = Literal["en", "hi", "hi_romanized", "hinglish"]
ExpectedPolicy = Literal["adult_general", "guarded_child", "guest_general"]
_REVIEW_RECEIPT_PATTERN = (
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
ReviewReceiptId = Annotated[str, Field(pattern=_REVIEW_RECEIPT_PATTERN)]


class ExpectedTurnConstraints(ContractModel):
    input_class: InputClass
    reply_mode: ReplyMode
    topic_terms_any: tuple[TopicTerm, ...] = Field(min_length=3, max_length=3)
    maximum_words: int = Field(ge=8, le=180)
    expected_policy: ExpectedPolicy

    @model_validator(mode="before")
    @classmethod
    def arrays_from_json_rows_are_tuples(cls, value: Any) -> Any:
        if isinstance(value, dict) and type(value.get("topic_terms_any")) is list:
            updated = dict(value)
            updated["topic_terms_any"] = tuple(updated["topic_terms_any"])
            return updated
        return value

    @field_validator("topic_terms_any")
    @classmethod
    def unique_topic_terms(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        folded = tuple(term.casefold() for term in value)
        if len(set(folded)) != len(folded):
            raise ValueError("duplicate topic term")
        return value


class BilingualEvalTurn(ContractModel):
    turn_id: str = Field(pattern=r"^[a-z0-9-]+$")
    user_text: str = Field(min_length=2, max_length=500)
    stt_language: Literal["en", "hi", "hinglish"]
    expected: ExpectedTurnConstraints


class BilingualPersonaCaseV1(ContractModel):
    schema_version: Literal["tuntun.bilingual-persona-case.v1"]
    case_id: str = Field(pattern=r"^[a-z0-9-]+$")
    topic_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9_.:-]+$")
    review_receipt_id: ReviewReceiptId
    identity_evidence: Literal["synthetic_verified", "synthetic_ambiguous"]
    expected_resolved_role: Literal["owner", "adult", "k2", "n1", "guest"]
    persona: PersonaProjection
    turns: tuple[BilingualEvalTurn, ...] = Field(min_length=2, max_length=4)

    @model_validator(mode="before")
    @classmethod
    def arrays_from_json_rows_are_tuples(cls, value: Any) -> Any:
        if isinstance(value, dict) and type(value.get("turns")) is list:
            updated = dict(value)
            updated["turns"] = tuple(updated["turns"])
            return updated
        return value

    @model_validator(mode="after")
    def corpus_row_is_closed_and_consistent(self) -> BilingualPersonaCaseV1:
        if len({turn.turn_id for turn in self.turns}) != len(self.turns):
            raise ValueError("duplicate bilingual turn id")
        if (
            self.identity_evidence == "synthetic_ambiguous"
            and self.expected_resolved_role != "guest"
        ):
            raise ValueError("ambiguous identity must resolve to guest")
        if self.persona.role == "guest" and self.expected_resolved_role != "guest":
            raise ValueError("guest persona must resolve to guest")
        if (
            self.persona.role != "guest"
            and self.identity_evidence == "synthetic_verified"
            and self.expected_resolved_role != self.persona.role
        ):
            raise ValueError("verified persona role mismatch")
        return self
