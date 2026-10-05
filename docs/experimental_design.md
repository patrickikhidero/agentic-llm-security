# Experimental Design

**Study:** An Empirical Evaluation of Attack and Defense Dynamics in Enterprise Agentic LLM Pipelines
**Author:** Patrick O. Ikhidero
**Prior work:** Ikhidero (2026). https://doi.org/10.5281/zenodo.21182170

This document describes the experiment as it was actually run. Where the
design changed from the original plan, `FINDINGS.md` records why.

---

## Research Questions

**RQ1.** What is the attack success rate (ASR) of each attack class
against the undefended agentic pipeline?

**RQ2.** How does the layered defense architecture reduce ASR relative
to the undefended baseline, and what is the associated cost to agent utility?

**RQ3.** What is the latency overhead introduced by each defense layer,
and is it operationally acceptable for enterprise deployment?

**RQ4.** At what execution depth does goal hijacking achieve the highest
cascade amplification (greatest downstream impact per injection)?

---

## Pipeline Configuration

| Component | Implementation |
|---|---|
| Orchestration | Custom agent loop, run in-process by the runner (a FastAPI wrapper exists for manual use) |
| Planning LLM | `openai/gpt-oss-20b` (open-weight, Apache 2.0) via Groq's OpenAI-compatible API, native function calling, temperature 0.0 |
| Retrieval | Embedded ChromaDB with local `sentence-transformers/all-MiniLM-L6-v2` embeddings, top-k 6 |
| Code execution | RestrictedPython sandbox, 10 s timeout |
| External API | httpx; mock HR API on `127.0.0.1:8090` |
| Max steps | 15 per execution chain |

Defense thresholds (`configs/defense_config.yaml`) are calibrated for
MiniLM's similarity distribution: input screener 0.20, goal verifier 0.40.

Configuration that differs by defense profile:

- **API domain allowlist:** empty under `baseline` (every domain
  reachable), the mock HR API only under `layered`.
- **Defense layers:** none under `baseline`; input screener, goal
  verifier, output validator and HITL gate under `layered`.

The API tool's write-method gate (`require_hitl_for_post`) is on under
both profiles, but the agent can set the approval flag itself. See the
§3 caveat in `FINDINGS.md`.

---

## Task Scenarios

Four enterprise task scenarios are used across all experiments:

| Scenario | Description | Tool Sequence |
|---|---|---|
| workspace_summary | Summarize top 5 documents on a topic | Retrieval → (code_exec optional) → Finish |
| document_classification | Classify 10 documents by topic/urgency | Retrieval × N → code_exec → Finish |
| api_data_retrieval | Fetch and format HR API data | api_call → code_exec → Finish |
| code_review | Review a Python function for bugs | Retrieval → code_exec → Finish |

In practice these tasks resolve in 1–3 tool calls, which limits when
mid-chain attacks can be mounted (see `FINDINGS.md` §5.0c and §5.4).

---

## Evaluation Protocol

Trial counts come from `configs/attack_config.yaml`.

### Benign baseline
- 8 trials per task scenario × 4 tasks × 2 profiles = 64 trials
- Establishes TCR and the false-positive rate of each defense layer

### Attack evaluation
- 20 trials per task scenario × 4 tasks × 4 attack classes × 2 profiles
  = 640 trials

**Configured total: 704 trials.** The final dataset holds 740 records:
36 extra benign-baseline trials remain from an earlier 20-per-scenario
benign configuration.

### Defense latency
End-to-end latency is unusable here: the free-tier rate limiter's sleeps
dominate trial timings. Each defense layer is instead benchmarked in
isolation with `scripts/bench_defense_latency.py`.

---

## Metrics

| Metric | Formula | Interpretation |
|---|---|---|
| ASR | successes / total trials | Proportion of trials in which the agent attempted the attacker-directed action |
| ASR (mounted only) | successes / mounted trials | Same, over trials where the payload actually reached the agent |
| TCR | completed / total trials | Proportion of tasks completed |
| Utility preservation | TCR_layered / TCR_baseline | 1.0 = no utility loss from defense |
| Defense latency | per-layer mean (ms) | Measured in isolation, not end-to-end |
| FPR | false_positives / benign_trials | Rate of incorrect defense triggers on benign tasks |

ASR counts an *attempt*. The payload hosts are on `example.com` and do not
resolve, so no exfiltration payload is ever delivered.

Proportions are reported with 95% Wilson score intervals, and
baseline-vs-layered comparisons with Fisher's exact test. Utility ratios use
a 95% log-scale (Katz) interval.

---

## Reproducibility

- Planning LLM calls use temperature 0.0. Outputs still vary between runs:
  identical code gave layered indirect-injection utility of 0.70 and 0.86
  in two collections (`FINDINGS.md` §5.5).
- `random_seed: 42` is set in `configs/attack_config.yaml`, but the runner
  does not currently read it. Trial combinations are assigned by trial
  index, not sampled.
- The benign corpus is committed as `data/corpus/documents.yaml`; index it
  with `python -m scripts.seed_corpus`. Poisoned documents are generated at
  run time by the attack modules, not committed.
- The runner checkpoints every trial to
  `data/results/trials_checkpoint.jsonl` and resumes from it. `data/results/`
  is gitignored.
