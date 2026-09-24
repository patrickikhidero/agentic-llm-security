"""
bench_defense_latency.py
────────────────────────
Measures per-call latency of each defense layer in isolation.

End-to-end request latency cannot be used to estimate defense overhead in
this setup: the free-tier provider quota forces a token-bucket rate
limiter whose sleeps dominate `execution_time_ms` (observed range 0.6s to
604s, median ~30s), swamping any millisecond-scale defense cost. Every
defense layer here runs locally though — regex screening, a local
sentence-transformers embedding, regex output validation, and an
in-process HITL policy check — so each can be timed directly and
honestly, independent of network and throttling.

Usage:
  python -m scripts.bench_defense_latency
"""

import statistics as stats
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import yaml  # noqa: E402

from src.defenses.goal_verifier import GoalVerifier  # noqa: E402
from src.defenses.hitl_gate import HITLGate  # noqa: E402
from src.defenses.input_screener import InputScreener  # noqa: E402
from src.defenses.output_validator import OutputValidator  # noqa: E402

N = 200

GOAL = ("Use the retrieval tool to find and summarize the top documents "
        "related to Q3 financial performance.")
PLAN = {"action": "TOOL_CALL", "tool": "retrieval",
        "tool_input": {"query": "Q3 financial performance"}, "reasoning": ""}
BENIGN_TEXT = ("Q3 Financial Performance Summary. Total quarterly revenue reached "
               "$48.2M, a 12 percent increase over Q2. Gross margin held steady at "
               "61 percent. Operating expenses grew 8 percent quarter over quarter.")
OUTPUT_TEXT = ("Q3 revenue was $48.2M, up 12% versus Q2, with gross margin flat at "
               "61%. Key risk: customer concentration in the top 10 accounts.")


def bench(label: str, fn) -> dict:
    fn()  # warm up (model load, regex compile) outside the measurement
    samples = []
    for _ in range(N):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000)
    samples.sort()
    return {
        "layer": label,
        "mean_ms": round(stats.mean(samples), 3),
        "median_ms": round(stats.median(samples), 3),
        "p95_ms": round(samples[int(0.95 * len(samples))], 3),
    }


def main() -> None:
    cfg = yaml.safe_load(open("configs/defense_config.yaml"))

    screener_both = InputScreener(cfg["input_screener"])
    screener_pattern = InputScreener({**cfg["input_screener"], "mode": "pattern"})
    verifier = OutputValidator(cfg["output_validator"])
    goal_verifier = GoalVerifier(cfg["goal_verifier"])
    gate = HITLGate({**cfg["hitl_gate"], "enabled": True})

    results = [
        bench("input_screener (pattern only)", lambda: screener_pattern.screen(BENIGN_TEXT)),
        bench("input_screener (pattern+classifier)", lambda: screener_both.screen(BENIGN_TEXT)),
        bench("goal_verifier (local embedding)", lambda: goal_verifier.verify(GOAL, PLAN, {})),
        bench("output_validator", lambda: verifier.validate(OUTPUT_TEXT)),
        bench("hitl_gate (policy check)", lambda: gate.check(PLAN)),
    ]

    width = max(len(r["layer"]) for r in results)
    print(f"\nPer-call defense latency (n={N} each, local CPU)\n")
    print(f"{'layer'.ljust(width)}  {'mean':>9}  {'median':>9}  {'p95':>9}")
    for r in results:
        print(f"{r['layer'].ljust(width)}  {r['mean_ms']:>8.3f}ms  "
              f"{r['median_ms']:>8.3f}ms  {r['p95_ms']:>8.3f}ms")
    print()


if __name__ == "__main__":
    main()
