# Jev cascade (experimental, default off)

Optional pre-filter: static rules → Jev → LLM (only if uncertain or Jev errors).

```yaml
llm_judge:
  provider: openai          # still required — escalate target
  eval_model: gpt-4o-mini
  openai_api_key: ${OPENAI_API_KEY}
  jev:
    enabled: true
    api_key: ${TYPESAFE_API_KEY}
    model: jev-1.13.0       # pinned; see below
    allow_below: 0          # noul < this → ALLOW (default 0: direct ALLOW is off)
    deny_above: 0.7         # noul >= this → DENY
```

**Data sharing.** Jev receives the same request JSON the LLM judge gets: the
policy, method, URL, headers (including credentials such as `Authorization`
and `Cookie`, capped at 4KB total) and up to 16KB of body. Enabling Jev sends
that data to TypeSafe in addition to your LLM provider, so make sure that is
acceptable before turning it on.

Jev answers each question with a **noul** score: its probability, in [0, 1],
that the answer is true. CrabTrap asks "does this request violate the policy?",
so the score is p(violates).

Pin a versioned `model`. Aliases such as `jev-latest` move to new releases,
which can shift scores under thresholds you already calibrated. Short-circuit
audits record the configured `model`.

- Admin evals do not run Jev. Replay checks static rules first, then uses the
  LLM if no rule matches. Labeled entries are always compared against their
  label. For unlabeled audit entries that Jev decided (`approved_by: jev`),
  agreement measures the replay decision against Jev's original decision. The
  eval view marks these entries. For unlabeled entries decided after Jev
  escalated (`jev+llm`), replay compares against the original LLM decision; the
  replay itself may still be decided by a static rule.
- Policy builder still needs a generative LLM.
- Audit rows show how a request was decided (`Channel` stays `llm`, same as static rules):
  - `approved_by: jev`: Jev decided alone (an ALLOW or DENY short-circuit). The model is the configured Jev `model`.
  - `approved_by: jev+llm`: Jev was consulted first (uncertain score or error) and the LLM decided. The model reads `<jev model> + <llm model>`, duration and tokens include Jev's, and the raw output starts with Jev's score or notes that Jev errored.
  - `approved_by: llm`: no Jev involved (cascade off, or Jev skipped because it was at capacity or its breaker was open).
  - `approved_by: llm-fallback`: Jev escalated but the LLM then errored, so the fallback mode decided. These rows are not counted as `jev+llm` (so LLM outages stay visible under the fallback filter), but the response still shows `<jev model> + <llm model>` and includes Jev's duration and tokens.
  The Audit Trail Approver filter has options for `jev` and `jev+llm`.
- Jev never queues: if all `max_concurrency` slots are busy or its circuit breaker is open, the request goes straight to the LLM and counts as `outcome=skipped`, not `error`. Worst-case latency on escalation is `jev.timeout` plus the LLM call.
- Jev reuses `llm_judge.max_concurrency` and the circuit-breaker settings (separate instance, same numbers).
- Jev's circuit breaker counts 5xx, 429, 401/403 (a bad or revoked API key), timeouts and transport errors. Other 4xx responses (for example a request Jev rejects as too large) escalate to the LLM as `outcome=error` but do not trip the breaker.
- Metrics: `crabtrap_jev_decisions_total{outcome=allow|deny|escalate|error|skipped}`, plus Jev's circuit breaker and call latency under the existing `crabtrap_llm_circuit_breaker_*` and `crabtrap_judge_latency_seconds` metrics with `provider="jev"`.
- A caller that disconnects mid-call does not count toward Jev's circuit breaker or `outcome=error`, and the request is not escalated to the LLM; Jev's own timeouts and transport errors still count.

Direct ALLOWs are opt-in. `allow_below` defaults to 0, so by default only DENY
short-circuits and everything else goes to the LLM. Jev gets the policy and the
request as JSON-escaped state, the same serialization the LLM judge uses, but
none of the LLM judge's system-prompt instructions to resist injection, so an
attacker-controlled body could try to push its score under the threshold.
Turn `allow_below` on only after calibrating it for your policy.

`allow_below` and `deny_above` default independently: set one and the other
keeps its default. Both must be in [0, 1] with `allow_below <= deny_above`.
Leaving `deny_above` unset uses the default 0.7. An explicit 0 is preserved
and denies every valid score (with `allow_below: 0`).
Setting `allow_below` equal to `deny_above` leaves no escalation band.

For reference, in a public smoke test (synthetic HTTP attack traffic, one
generic policy) benign requests mostly scored 0.1 to 0.3 and the lowest-scoring
attack scored 0.26. At `allow_below: 0.1` almost every benign request still
escalated, which made the cascade cost more than the LLM alone on benign-heavy
traffic. Scores shift with the policy text and the Jev version, so recalibrate
when either changes. A lower value is safer; a higher one saves more LLM calls
but lets more requests skip the LLM.

## Injection check

`internal/judge/jev_injection_eval_test.go` measures how far attacker-controlled
text moves Jev's score. It scores each attack plain, then with injection text
added through the query string, a header, the body, and an "ignore previous
instructions" override that includes a fake policy fragment. It calls the real
Jev API, so it only runs when you opt in (a key alone is not enough):

```
JEV_INJECTION_EVAL=1 TYPESAFE_API_KEY=... go test ./internal/judge -run TestJevInjectionEval -v -count=1
```

Variants whose injection text is removed or truncated by request serialization
are reported as skipped and excluded from the score counts.

It uses a small built-in attack set and policy by default. Set
`JEV_INJECTION_DATASET` (JSONL of `id, method, url, headers, body, attack_tag`)
and `JEV_INJECTION_POLICY_FILE` to replay your own.

One run on `jev-1.13.0` with the generic anti-exploit policy, using the 11 Log
Forging attacks Jev was least sure about in the public smoke test (plain scores
0.36 to 0.60), 4 variants each (44 injected requests). The 0.26 attack
mentioned above is not in this set: the smoke test did not keep per-request
scores for escalated rows, and rescoring those Log Forging attacks gave 0.36
at the lowest, so the request closest to the threshold was not covered.

- No injected score fell below 0.2, or even 0.3. The lowest was 0.32, against a
  lowest plain score of 0.36. No injected score was more than 0.07 below its
  plain score.
- Text in the query string and the override raised scores (the override raised
  every one of them to 0.86 or higher), so those channels made the request look
  more suspicious, not less. Body and header text moved scores by 0.08 or less
  in either direction.
- The built-in synthetic set (6 attacks, 24 injected requests) behaved the same:
  the lowest injected score was 0.78, against plain scores of 0.79 to 0.99.

Read this as a sanity check, not proof. It is a small set, one attack family and
one policy, and the injections are simple, hand-written strings, not optimized
against Jev. The weakest attack in this run (0.36) sits 0.16 above an
`allow_below` of 0.2, but the smoke test saw an attack at 0.26, only 0.06
above it, and a different policy or Jev version can shift both. Direct ALLOWs stay opt-in, and anyone turning them on should rerun this with
their own policy and attacks first.

