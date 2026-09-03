# ADR 0001: LangGraph is orchestration, not memory

Status: accepted for Phase 1.

LangGraph coordinates the reviewed sequence of typed conversation calls. Both the
linear and graph engines call the same production `PersonalizedTurnContextProvider`
after transcription; language and persona behavior is not a graph-specific prompt.

The in-memory checkpointer may contain only the turn identifier, phase, cancellation
state, and bounded content commitments. `EphemeralTurnContext` exclusively owns raw
audio, transcripts, rendered provider context, answers, and synthesized audio.
`TurnLifecycleRegistry` owns only process-local start/played cleanup flags and is
neither conversation memory nor checkpoint content. LangGraph Store is prohibited.

Every terminal path attempts to clear ephemeral content, delete the checkpoint
thread, call `finish` after any start attempt, and clear lifecycle state. Cleanup
failures are recorded with content-free reason codes and do not replace a primary
turn failure. The authoritative session-ended handler separately clears the
session-scoped language prior.
