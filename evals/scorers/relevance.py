from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable

_TOKEN = re.compile(r"[^\W_]+", re.UNICODE)


def score_relevance_micros(answer: str, topic_terms_any: Iterable[str]) -> int:
    if type(answer) is not str:
        raise TypeError("answer must be an exact str")
    terms = tuple(_normalize(term) for term in topic_terms_any)
    if len(terms) != 3 or len(set(terms)) != 3:
        raise ValueError("relevance requires three reviewed topic terms")
    answer_text = _normalize(answer)
    matched = sum(term in answer_text for term in terms)
    return round(matched / len(terms) * 1_000_000)


def is_relevant(
    answer: str,
    topic_terms_any: Iterable[str],
    *,
    minimum_micros: int = 666_667,
) -> bool:
    if type(minimum_micros) is not int or not 0 <= minimum_micros <= 1_000_000:
        raise ValueError("invalid relevance threshold")
    return score_relevance_micros(answer, topic_terms_any) >= minimum_micros


def _normalize(value: str) -> str:
    if type(value) is not str:
        raise TypeError("topic term must be an exact str")
    tokens = _TOKEN.findall(unicodedata.normalize("NFKC", value).casefold())
    if not tokens:
        raise ValueError("topic term must contain text")
    return " ".join(tokens)
