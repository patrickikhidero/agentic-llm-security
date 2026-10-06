"""Draw the paper's Figure 2 from the statistics produced by paper_stats.py.

Run from the repo root:
  ./venv/bin/python scripts/paper_stats.py --json data/results/paper_stats.json
  ./venv/bin/python scripts/paper_figures.py data/results/paper_stats.json out.png

Panel A: attack success rate by class, baseline vs layered, with 95% Wilson
intervals. Panel B: utility preservation (TCR layered / TCR baseline) with
95% Katz intervals; the two injection classes are pooled over both
collections (FINDINGS.md §5.5). Two panels rather than one dual-axis chart,
since the measures have different scales.
"""
import json
import sys

import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402

BASELINE = '#2a78d6'
LAYERED = '#eb6834'
INK = '#1f1f1e'
MUTED = '#6b6a63'
GRID = '#e4e3dc'
CLASSES = [('indirect_injection', 'Indirect prompt\ninjection'),
           ('goal_hijacking', 'Goal\nhijacking'),
           ('cascade_exploit', 'Cascade\nexploitation'),
           ('tool_poisoning', 'Tool description\npoisoning')]


def main(stats_path, out_path):
    t = json.load(open(stats_path))['table1']
    plt.rcParams.update({'font.family': 'serif', 'font.serif': ['Times New Roman', 'Times', 'DejaVu Serif'],
                         'font.size': 10, 'axes.edgecolor': MUTED, 'axes.labelcolor': INK,
                         'xtick.color': INK, 'ytick.color': INK, 'hatch.linewidth': 0.8})
    fig, (ax, bx) = plt.subplots(1, 2, figsize=(7.0, 3.3), gridspec_kw={'width_ratios': [1.55, 1]})

    # ── Panel A: ASR ────────────────────────────────────────────────────────────
    w = 0.36
    for i, (cls, _) in enumerate(CLASSES):
        for j, (key, color, hatch) in enumerate((('asr_baseline', BASELINE, None),
                                                 ('asr_layered', LAYERED, '////'))):
            k, n, p, (lo, hi) = t[cls][key]
            x = i + (j - 0.5) * (w + 0.03)
            ax.bar(x, p, w, color=color if hatch is None else 'white', edgecolor=color,
                   hatch=hatch, linewidth=1.0, zorder=2)
            ax.errorbar(x, p, yerr=[[p - lo], [hi - p]], fmt='none', ecolor=INK, elinewidth=0.8,
                        capsize=2.5, zorder=3)
            ax.text(x, hi + 1.2, f'{p:.1f}', ha='center', va='bottom', fontsize=8, color=INK)
    ax.set_xticks(range(len(CLASSES)), [label for _, label in CLASSES], fontsize=8.5)
    ax.set_ylabel('Attack success rate (%)')
    ax.set_ylim(0, 42)
    ax.set_title('A. Attack success rate', loc='left', fontsize=10, color=INK)
    ax.grid(axis='y', color=GRID, linewidth=0.6, zorder=0)
    ax.bar(0, 0, color=BASELINE, label='Baseline (undefended)')
    ax.bar(0, 0, color='white', edgecolor=LAYERED, hatch='////', label='Layered defense')
    ax.legend(frameon=False, fontsize=8.5, loc='upper left')

    # ── Panel B: utility preservation ───────────────────────────────────────────
    for i, (cls, label) in enumerate(CLASSES):
        u, lo, hi = t[cls]['utility']
        y = len(CLASSES) - 1 - i
        bx.errorbar(u, y, xerr=[[u - lo], [hi - u]], fmt='o', color=INK, markersize=5,
                    elinewidth=0.9, capsize=2.5, zorder=3)
        bx.text(hi + 0.012, y, f'{u:.2f}' + ('†' if t[cls]['pooled'] else ''), va='center',
                fontsize=8, color=INK)
    bx.axvline(1.0, color=MUTED, linewidth=0.8, linestyle='--', zorder=1)
    bx.set_yticks(range(len(CLASSES)), [label.replace('\n', ' ') for _, label in reversed(CLASSES)],
                  fontsize=8.5)
    bx.set_xlim(0.5, 1.15)
    bx.set_ylim(-0.6, len(CLASSES) - 0.4)
    bx.set_xlabel('TCR layered ÷ TCR baseline')
    bx.set_title('B. Utility preservation', loc='left', fontsize=10, color=INK)
    bx.grid(axis='x', color=GRID, linewidth=0.6, zorder=0)

    for a in (ax, bx):
        for side in ('top', 'right'):
            a.spines[side].set_visible(False)
    fig.tight_layout()
    fig.savefig(out_path, dpi=300, facecolor='white')


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
