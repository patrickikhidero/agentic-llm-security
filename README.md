# Agentic LLM Pipeline Security — Experimental Repository

**Companion code for:**
> Ikhidero, P. O. (2026). *An Empirical Evaluation of Attack and Defense Dynamics in Enterprise Agentic LLM Pipelines.* Zenodo. [DOI to be assigned]

**Prior work:**
> Ikhidero, P. O. (2026). *LLM Integration Security in Enterprise Backend Systems: A Systematic Review of Emerging Attack Surfaces in Production API Environments.* Zenodo. https://doi.org/10.5281/zenodo.21182170

---

## Overview

This repository contains the experimental pipeline used to empirically evaluate four classes of attack on
agentic LLM pipelines against a purpose-built multi-step enterprise agentic system:

| Attack Class | Module |
|---|---|
| Indirect Prompt Injection | `src/attacks/indirect_injection.py` |
| Goal Hijacking | `src/attacks/goal_hijacking.py` |
| Cascade Exploitation | `src/attacks/cascade_exploit.py` |
| Tool Description Poisoning | `src/attacks/tool_poisoning.py` |

Each attack is mounted against a multi-step agentic pipeline with three real tool integrations:
- **Retrieval Tool** — embedded ChromaDB RAG over an enterprise document corpus
- **Code Execution Tool** — RestrictedPython sandbox
- **External API Tool** — REST caller with a per-profile domain allowlist, exercised against a local mock HR API

The planning model is `openai/gpt-oss-20b`, an open-weight (Apache 2.0) model, called through
Groq's OpenAI-compatible API. Each trial runs under one of two defense profiles: `baseline`
(undefended) or `layered` (input screener, goal verifier, output validator and HITL gate).

Results, methodology changes and every bug found during the evaluation are logged in
[`FINDINGS.md`](FINDINGS.md).

---

## Repository Structure

```
agentic-llm-security/
├── src/
│   ├── agent/                  # Core agentic pipeline
│   │   ├── orchestrator.py     # Agent loop and defense hooks (plus a FastAPI wrapper for manual use)
│   │   ├── planner.py          # LLM planning module (native function calling)
│   │   ├── context_manager.py  # Context window management
│   │   └── memory.py           # Session memory
│   ├── common/
│   │   ├── llm_client.py       # Groq client with rate limiting and retries
│   │   └── embeddings.py       # Local sentence-transformers embeddings
│   ├── tools/                  # Tool integrations
│   │   ├── retrieval_tool.py   # ChromaDB RAG tool
│   │   ├── code_exec_tool.py   # Sandboxed code execution
│   │   ├── api_call_tool.py    # External REST API tool
│   │   └── mock_hr_api.py      # Local mock HR API (127.0.0.1:8090)
│   ├── attacks/                # Attack scenario implementations and scoring
│   │   ├── indirect_injection.py
│   │   ├── goal_hijacking.py
│   │   ├── cascade_exploit.py
│   │   ├── tool_poisoning.py
│   │   └── scoring.py
│   ├── defenses/               # Defensive layer implementations
│   │   ├── input_screener.py   # Injection-pattern and similarity screening
│   │   ├── goal_verifier.py    # Goal-consistency verification
│   │   ├── output_validator.py # Output policy validation
│   │   └── hitl_gate.py        # Human-in-the-loop confirmation gate
│   └── evaluation/             # Metrics and evaluation harness
│       ├── metrics.py          # ASR, utility, FPR calculations
│       ├── runner.py           # Experiment runner (checkpoints and resumes)
│       └── reporter.py         # Results export to CSV/JSON
├── scripts/
│   ├── seed_corpus.py          # Index the benign corpus into ChromaDB
│   ├── resume_run.sh           # Resume a full evaluation from its checkpoint
│   ├── bench_defense_latency.py  # Per-layer defense latency benchmark
│   └── audit_scoring.py        # Scoring audit for bugs 11/12 (see FINDINGS.md)
├── tests/
│   ├── test_attacks.py
│   └── test_defenses.py
├── data/
│   ├── corpus/documents.yaml   # Benign enterprise document corpus
│   └── results/                # Experiment output (gitignored)
├── docs/
│   ├── experimental_design.md
│   └── attack_scenarios.md
├── configs/
│   ├── pipeline_config.yaml
│   ├── attack_config.yaml
│   └── defense_config.yaml
├── FINDINGS.md                 # Evaluation log: results, decisions, bugs
├── requirements.txt
├── .env.example
├── .gitignore
├── LICENSE
└── README.md
```

---

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/[your-username]/agentic-llm-security.git
cd agentic-llm-security
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env and add your Groq API key (free at https://console.groq.com)
```

### 3. Index the corpus

```bash
python -m scripts.seed_corpus
```

The runner starts the mock HR API itself and calls the pipeline in-process, so no server
needs to be running.

### 4. Run trials

```bash
# Benign tasks only, under both defense profiles
python -m src.evaluation.runner --mode benign

# One attack class, under one defense profile
python -m src.evaluation.runner --mode attack --attack indirect_injection --defense layered

# The full evaluation: every class, both profiles
python -m src.evaluation.runner --mode full_eval --config configs/attack_config.yaml
```

The full evaluation is 704 trials. On Groq's free tier the daily token quota allows roughly
100–120 trials a day. When the quota runs out the runner checkpoints and exits; rerun the same
command, or `scripts/resume_run.sh`, to continue where it stopped.

### 5. Run the tests

```bash
python -m pytest
```

Results will be saved to `data/results/`.

---

## Experimental Design

See [`docs/experimental_design.md`](docs/experimental_design.md) for the full methodology,
including:
- Task scenarios and benign baseline setup
- Attack scenario specifications per attack class
- Defense layer configurations (individual and layered)
- Metrics: Attack Success Rate (ASR), Task Completion Rate (TCR), latency overhead

---

## Metrics Collected

| Metric | Description |
|---|---|
| **ASR** | Attack Success Rate — % of trials in which the agent attempted the attacker-directed action |
| **TCR** | Task Completion Rate — % of tasks completed |
| **Utility preservation** | TCR under `layered` ÷ TCR under `baseline` |
| **Latency** | Mean per-call time of each defense layer (ms), benchmarked in isolation |
| **FPR** | False Positive Rate of input/output classifiers |

---

## License

MIT License — see [`LICENSE`](LICENSE)

---

## Citation

If you use this code in your research, please cite:

```bibtex
@misc{ikhidero2026agentic,
  author    = {Ikhidero, Patrick O.},
  title     = {An Empirical Evaluation of Attack and Defense Dynamics
               in Enterprise Agentic {LLM} Pipelines},
  year      = {2026},
  publisher = {Zenodo},
  doi       = {[to be assigned on upload]}
}

@misc{ikhidero2026llm,
  author    = {Ikhidero, Patrick O.},
  title     = {{LLM} Integration Security in Enterprise Backend Systems:
               A Systematic Review of Emerging Attack Surfaces
               in Production {API} Environments},
  year      = {2026},
  publisher = {Zenodo},
  doi       = {10.5281/zenodo.21182170}
}
```
