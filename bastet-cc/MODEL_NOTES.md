# MODEL_NOTES — ais3/nemotron-3-ultra-550b structured-output behavior

Measured 2026-07-25 against `https://llm-api.zoolab.org/v1` (probe scripts, ~25 real calls).
These observations are the basis for the parsing strategy in `bastet_cc/llm.py`.

## Response shape

- OpenAI-compatible `/chat/completions`. Top-level keys: `id, created, model, object,
  system_fingerprint, choices, usage`. `usage` is always present with real
  `prompt_tokens` / `completion_tokens` (verified: a 240,022-token prompt reports 240022).
- `message` keys: `content, role, provider_specific_fields`;
  `provider_specific_fields = {"refusal": null, "reasoning": null}` on every call observed.
- **`content` was never null** in any probe (including truncation and 240K-token prompts).
  llm.py still guards with `content or ""` — cost is one line.
- `finish_reason` observed: `stop` (normal), `length` (hit `max_tokens`, JSON cut mid-string).
  No `content_filter` / refusal observed on vulnerability-detection prompts; refusal risk
  for this domain is effectively zero (it happily reports reentrancy attack scenarios).

## Structured output modes

| mode | works | latency (same prompt) | notes |
|---|---|---|---|
| plain + schema in system prompt | yes | 0.6–1.2s | valid bare JSON when system says "JSON only" |
| `response_format={"type":"json_object"}` | yes | 0.6–0.8s | valid bare JSON, no fences |
| `response_format={"type":"json_schema", strict:true}` | yes | **18.5s** | ~15–18s overhead (server-side grammar compile), output no better than json_object |

**Decision: use `json_object`, never `json_schema`.** The strict mode's 15x latency
penalty would erase the entire routing cost win, and json_object output already parsed
on every probe. Schema conformance is enforced by the system prompt plus lenient parsing.

## Fence / free-form risk

With `json_object` or a "JSON only" system prompt: bare JSON every time.
With a loose prompt ("give the result as JSON", no response_format): the model returns
a ```` ```json ```` fenced block **with its own invented schema** (keys like
`vulnerability_type`, severity `"Critical"`). Consequences:

1. Always send `response_format=json_object` AND a system prompt that pins the exact schema.
2. Lenient fallback (fence strip → first-valid-JSON scan) stays in, for other models
   (llama/gemma arms) and for repair-call outputs.
3. Severity normalization must fold `Critical` → `High` (findings.py).
4. Upstream detector prompts end with their own "Output Format" section saying
   "output a empty array" — the model may emit a bare `[]`/`[...]` instead of
   `{"findings": []}`. llm.py wraps a top-level JSON array into `{"findings": [...]}`
   when the requested schema has a `findings` property.

## Context window and errors

- **Max context: 262,144 tokens** (prompt + max_tokens combined). A 240K-token prompt
  succeeds (18.7s); beyond the limit the endpoint returns **HTTP 400** with
  `ContextWindowExceededError` / "maximum context length" in the error message
  → classified `context_overflow`, not retried.
- Unknown model → HTTP 403 (key-scoped model list), not 404.
- Errors arrive as `{"error": {"message": ..., "type": ...}}` JSON bodies (LiteLLM proxy
  in front of hosted vLLM).

## Determinism and latency

- temperature=0 is **not** byte-deterministic: identical calls returned 177 vs 167
  completion tokens (same verdict/content, different wording). Reproducibility therefore
  comes from persisted artifacts (results.jsonl), not from re-calling — consistent with
  DESIGN principle 2.
- Latency: 0.2–1.2s for small prompts; ~2–11s under 8-way concurrency (queueing at the
  endpoint, wall for 8 parallel real calls: 10.9s); ~18s for 240K-token prompts.
- Empty-finding responses are ~9 output tokens — negative routing verdicts are near-free.

## Parsing strategy adopted (llm.py)

1. `response_format={"type":"json_object"}` whenever a schema is requested; on a 400
   complaining about response_format (other models may lack it), permanently fall back
   to prompt-embedded schema for that client instance.
2. Parse: direct `json.loads` → strip ``` fences → scan for first valid JSON value.
3. Top-level array wrapped as `{"findings": [...]}` if the schema expects `findings`.
4. Still unparsable → one "repair" call (return the malformed text, ask for corrected
   JSON only) → still failing → `LLMResult(error="json_invalid")`, never raises.
5. Retry 429/5xx/timeout/connection with 2s/8s/32s backoff (max_retries=3 → 4 attempts).
6. `finish_reason=length` with a schema request is recorded as `error="truncated"` when
   the tail cannot be parsed (probe confirmed mid-string cuts).
