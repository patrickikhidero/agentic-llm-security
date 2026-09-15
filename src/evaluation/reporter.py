"""
reporter.py
───────────
Exports evaluation results to CSV, JSON, and console summary table.
Results feed directly into notebooks/03_results_analysis.ipynb
"""

import json
import logging
from pathlib import Path

import pandas as pd
from rich.console import Console
from rich.table import Table

logger   = logging.getLogger(__name__)
console  = Console()


class Reporter:
    def __init__(self, results_dir: Path) -> None:
        self.results_dir = results_dir

    def save_trials(self, df: pd.DataFrame) -> Path:
        path = self.results_dir / "trials.csv"
        df.to_csv(path, index=False)
        logger.info(f"Trial data saved: {path}")
        return path

    def save_summary(self, report: dict) -> Path:
        path = self.results_dir / "summary.json"
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        logger.info(f"Summary report saved: {path}")
        self._print_summary_table(report)
        return path

    def _print_summary_table(self, report: dict) -> None:
        """Print a Rich-formatted summary table to console."""
        table = Table(title="Evaluation Summary", show_header=True,
                      header_style="bold white on dark_blue")
        table.add_column("Attack Class",        style="bold")
        table.add_column("ASR Baseline (%)",    justify="right")
        table.add_column("ASR Layered (%)",     justify="right")
        table.add_column("Defense Reduction",   justify="right")

        for cls, data in report.get("per_attack_class", {}).items():
            asr_b = data["asr_baseline"].get("asr_pct")
            asr_l = data["asr_layered"].get("asr_pct")
            reduction = (
                f"{asr_b - asr_l:.1f}pp"
                if asr_b is not None and asr_l is not None
                else "N/A"
            )
            table.add_row(
                cls.replace("_", " ").title(),
                f"{asr_b:.1f}" if asr_b is not None else "N/A",
                f"{asr_l:.1f}" if asr_l is not None else "N/A",
                reduction,
            )

        console.print(table)

        up = report.get("benign_utility_preservation", {})
        lat = report.get("latency_overhead", {})
        console.print(f"\n[bold]Utility Preservation:[/bold] "
                      f"{up.get('utility_preservation', 'N/A')} "
                      f"(baseline TCR={up.get('tcr_baseline')}% → "
                      f"layered TCR={up.get('tcr_layered')}%)")
        console.print(f"[bold]Latency Overhead:[/bold] "
                      f"+{lat.get('overhead_ms', 'N/A')}ms "
                      f"({lat.get('overhead_pct', 'N/A')}% increase)")
