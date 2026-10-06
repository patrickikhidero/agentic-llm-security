# Agentic LLM Pipeline Security — Experimental Repository

**Companion code for:**
> Ikhidero, P. O. (2026). *An Empirical Evaluation of Attack and Defense Dynamics in Enterprise Agentic LLM Pipelines.* Zenodo. [DOI to be assigned]

**Prior work:**
> Ikhidero, P. O. (2026). *LLM Integration Security in Enterprise Backend Systems: A Systematic Review of Emerging Attack Surfaces in Production API Environments.* Zenodo. https://doi.org/10.5281/zenodo.21182170

## Overview

A multi-step enterprise agent, built for this study, is attacked with four attack classes, with
and without a layered defense:

| Attack class | Module |
|---|---|
| Indirect prompt injection | `src/attacks/indirect_injection.py` |
| Goal hijacking | `src/attacks/goal_hijacking.py` |
| Cascade exploitation | `src/attacks/cascade_exploit.py` |
| Tool description poisoning | `src/attacks/tool_poisoning.py` |

The agent plans with `openai/gpt-oss-20b` (open-weight, Apache 2.0) via Groq and has three
tools: ChromaDB retrieval, a RestrictedPython sandbox, and an API caller pointed at a local mock
HR API. Each trial runs under `baseline` (no defenses) or `layered` (input screener, goal
verifier, output validator, HITL gate, plus an API domain allowlist).

## Results

From 740 trials (n = 80 per class and profile):

| Attack class | ASR baseline | ASR layered | Utility (layered ÷ baseline TCR) |
|---|---|---|---|
| Indirect prompt injection | 7.5% | 0% | 0.78 |
| Goal hijacking | 7.5% | 0% | 0.98 |
| Cascade exploitation | 0% | 0% | 0.81 |
| Tool description poisoning | 25.0% | 0% | 0.68 |

The layered defense stopped every attack, at a cost in completed tasks that varied by class.
Cascade attacks mostly could not be mounted, because tasks finished within a few tool calls.
See the paper for details, and [`FINDINGS.md`](FINDINGS.md) for the full evaluation log:
decisions, bugs found, and corrections.

## Scope

This repository contains prompt-injection payloads for research use. Attacker hosts are
subdomains of `example.com` and never resolve, so ASR counts *attempted* attacker actions;
no payload is ever delivered.

## Quick start

Requires Python 3.11. The first run needs internet access to download the
`all-MiniLM-L6-v2` embedding model from Hugging Face.

```bash
git clone https://github.com/[your-username]/agentic-llm-security.git
cd agentic-llm-security
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m pytest                      # no API key needed
```

To run trials, add a Groq API key (free at https://console.groq.com):

```bash
cp .env.example .env                  # then set GROQ_API_KEY
python -m scripts.seed_corpus         # index the document corpus

python -m src.evaluation.runner --mode benign
python -m src.evaluation.runner --mode attack --attack indirect_injection --defense layered
python -m src.evaluation.runner --mode full_eval --config configs/attack_config.yaml
```

Trials are checkpointed to `data/results/`. The full evaluation configures 704 trials; the
published dataset holds 740, including 36 benign trials from an earlier configuration. During
the study, Groq's free tier allowed about 100–120 trials a day. When the quota runs out, the
runner saves and exits; rerun the command, or `scripts/resume_run.sh` (zsh, expects `./venv`),
to continue.

## Reproducing the paper

The trial data will be published at [data DOI]. Place it in `data/results/`, then:

```bash
python scripts/paper_stats.py --json data/results/paper_stats.json   # Table 1 and all statistics
python scripts/paper_figures.py data/results/paper_stats.json figure2.png
python scripts/paper_pipeline_figure.py figure1.png
```

## Documentation

- [`docs/experimental_design.md`](docs/experimental_design.md): pipeline, tasks, protocol, metrics
- [`docs/attack_scenarios.md`](docs/attack_scenarios.md): the exact attack combinations run
- [`FINDINGS.md`](FINDINGS.md): evaluation log

Metrics: **ASR**, the share of trials in which the agent attempted the attacker's action;
**TCR**, the share of tasks completed; **utility**, layered TCR ÷ baseline TCR; **FPR**, how
often each of the four defense layers fired on benign tasks; **latency**, per-layer cost,
benchmarked in isolation (`scripts/bench_defense_latency.py`).

## License

Code: MIT — see [`LICENSE`](LICENSE).

## Citation

```bibtex
@misc{ikhidero2026empirical,
  author    = {Ikhidero, Patrick O.},
  title     = {An Empirical Evaluation of Attack and Defense Dynamics
               in Enterprise Agentic {LLM} Pipelines},
  year      = {2026},
  publisher = {Zenodo},
  doi       = {[to be assigned on upload]}
}
```
