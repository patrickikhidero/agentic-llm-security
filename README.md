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

Each attack is mounted against a FastAPI-based agentic pipeline with three real tool integrations:
- **Retrieval Tool** — ChromaDB-backed RAG over an enterprise document corpus
- **Code Execution Tool** — sandboxed Python subprocess executor
- **External API Tool** — REST endpoint caller (mocked and live variants)

---

## Repository Structure

```
agentic-llm-security/
├── src/
│   ├── agent/                  # Core agentic pipeline
│   │   ├── orchestrator.py     # Main agent loop (FastAPI)
│   │   ├── planner.py          # LLM planning module
│   │   ├── context_manager.py  # Context window management
│   │   └── memory.py           # Session memory
│   ├── tools/                  # Tool integrations
│   │   ├── retrieval_tool.py   # ChromaDB RAG tool
│   │   ├── code_exec_tool.py   # Sandboxed code execution
│   │   └── api_call_tool.py    # External REST API tool
│   ├── attacks/                # Attack scenario implementations
│   │   ├── indirect_injection.py
│   │   ├── goal_hijacking.py
│   │   ├── cascade_exploit.py
│   │   └── tool_poisoning.py
│   ├── defenses/               # Defensive layer implementations
│   │   ├── input_screener.py   # Classifier-based input screening
│   │   ├── goal_verifier.py    # Goal-consistency verification
│   │   ├── output_validator.py # Output schema validation
│   │   └── hitl_gate.py        # Human-in-the-loop confirmation gate
│   └── evaluation/             # Metrics and evaluation harness
│       ├── metrics.py          # ASR, utility, latency calculations
│       ├── runner.py           # Experiment runner
│       └── reporter.py         # Results export to CSV/JSON
├── tests/                      # Unit and integration tests
│   ├── test_agent.py
│   ├── test_tools.py
│   ├── test_attacks.py
│   └── test_defenses.py
├── data/
│   ├── corpus/                 # Benign enterprise document corpus
│   ├── poisoned/               # Adversarially crafted injection documents
│   └── results/                # Experiment output data
├── notebooks/
│   ├── 01_pipeline_demo.ipynb
│   ├── 02_attack_evaluation.ipynb
│   └── 03_results_analysis.ipynb
├── docs/
│   ├── experimental_design.md
│   ├── attack_scenarios.md
│   └── defense_architecture.md
├── configs/
│   ├── pipeline_config.yaml
│   ├── attack_config.yaml
│   └── defense_config.yaml
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
# Edit .env and add your LLM API keys
```

### 3. Run the pipeline

```bash
# Start the agentic pipeline server
uvicorn src.agent.orchestrator:app --reload --port 8000

# In a separate terminal, run a benign task
python -m src.evaluation.runner --mode benign --task workspace_summary

# Run an attack scenario
python -m src.evaluation.runner --mode attack --attack indirect_injection --task workspace_summary
```

### 4. Run full evaluation

```bash
python -m src.evaluation.runner --mode full_eval --config configs/attack_config.yaml
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
| **ASR** | Attack Success Rate — % of attack attempts achieving attacker goal |
| **TCR** | Task Completion Rate — % of benign tasks completed correctly |
| **TCR-D** | Task Completion Rate under Defense — utility preservation measure |
| **Latency** | Mean response time per defense layer (ms) |
| **FPR** | False Positive Rate of input/output classifiers |

---

## License

MIT License — see [`LICENSE`](LICENSE)

---

## Citation

If you use this code in your research, please cite:

```bibtex
@misc{ikhidero2026agentic,
  author    = {Ikhidero, Prosper O.},
  title     = {An Empirical Evaluation of Attack and Defense Dynamics
               in Enterprise Agentic {LLM} Pipelines},
  year      = {2026},
  publisher = {Zenodo},
  doi       = {[to be assigned on upload]}
}

@misc{ikhidero2026llm,
  author    = {Ikhidero, Prosper O.},
  title     = {{LLM} Integration Security in Enterprise Backend Systems:
               A Systematic Review of Emerging Attack Surfaces
               in Production {API} Environments},
  year      = {2026},
  publisher = {Zenodo},
  doi       = {10.5281/zenodo.21182170}
}
```
