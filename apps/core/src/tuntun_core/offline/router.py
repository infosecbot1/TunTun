from __future__ import annotations

from tuntun_core.domain.offline import ConsentChallenge, OfflineMatch
from tuntun_core.offline.grammar import parse_offline


class OfflineTextRouter:
    def route(self, hypothesis: str, challenge: ConsentChallenge | None) -> OfflineMatch:
        return parse_offline(hypothesis, challenge)
