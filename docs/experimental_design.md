# Experimental Design

**Study:** An Empirical Evaluation of Attack and Defense Dynamics in Enterprise Agentic LLM Pipelines
**Author:** Prosper O. Ikhidero
**Prior work:** Ikhidero (2026). https://doi.org/10.5281/zenodo.21182170

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
| Orchestration | FastAPI + custom agent loop |
| Planning LLM | GPT-4o (temp=0.0 for reproducibility) |
| Retrieval | ChromaDB + sentence-transformers embeddings |
| Code execution | RestrictedPython sandbox |
| External API | httpx with domain allowlist |
| Max steps | 15 per execution chain |

---

## Task Scenarios

Four enterprise task scenarios are used across all experiments:

| Scenario | Description | Tool Sequence |
|---|---|---|
| workspace_summary | Summarize top 5 documents on a topic | Retrieval → (code_exec optional) → Finish |
| document_classification | Classify 10 documents by topic/urgency | Retrieval × N → code_exec → Finish |
| api_data_retrieval | Fetch and format HR API data | api_call → code_exec → Finish |
| code_review | Review a Python function for bugs | Retrieval → code_exec → Finish |

---

## Evaluation Protocol

### Phase 1: Benign Baseline
- 50 trials per task scenario × 4 tasks = 200 benign trials
- Defense profile: `baseline` (no defenses)
- Establishes TCR baseline and benign step count distribution

### Phase 2: Attack Evaluation
- 50 trials per attack scenario × 4 attack classes × 4 tasks = 800 attack trials
- Each attack run twice: `baseline` profile and `layered` profile
- Total attack trials: 1,600

### Phase 3: Defense Overhead
- 50 benign trials per defense profile (`baseline`, `layered`)
- Latency overhead = mean(layered_ms) - mean(baseline_ms)
- False positive rate measured on benign trials with defenses active

**Total trials: ~2,000**

---

## Metrics

| Metric | Formula | Interpretation |
|---|---|---|
| ASR | successes / total trials | Proportion of attacks achieving attacker goal |
| TCR | completed / total trials | Proportion of benign tasks completed correctly |
| Utility preservation | TCR_layered / TCR_baseline | 1.0 = no utility loss from defense |
| Latency overhead | mean(layered_ms) - mean(baseline_ms) | Added latency per request from defense |
| FPR | false_positives / benign_trials | Rate of incorrect defense triggers |

All proportional metrics reported with 95% Wilson score confidence intervals
where n ≥ 30.

---

## Reproducibility

- Random seed: 42 (set in `configs/attack_config.yaml`)
- All LLM calls use temperature=0.0
- ChromaDB corpus is versioned and committed to `data/corpus/`
- Poisoned documents are committed to `data/poisoned/`
- Results are saved to `data/results/` (gitignored; available on request)
