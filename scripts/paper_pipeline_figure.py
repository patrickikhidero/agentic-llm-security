"""Draw the paper's Figure 1: the experimental pipeline, its defense layers,
and where each attack class enters.

Run from the repo root: ./venv/bin/python scripts/paper_pipeline_figure.py out.png
"""
import sys

import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

INK = '#1f1f1e'
MUTED = '#6b6a63'
DEFENSE = '#eb6834'
ATTACK = '#2a78d6'
FILL = '#f4f3ee'


def box(ax, x, y, w, h, title, sub=None, edge=INK, fill=FILL, lw=1.0, dashed=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle='round,pad=0.02,rounding_size=0.08',
                                facecolor=fill, edgecolor=edge, linewidth=lw,
                                linestyle='--' if dashed else '-'))
    if sub:
        ax.text(x + w / 2, y + h * 0.63, title, ha='center', va='center', fontsize=8.6,
                color=INK, fontweight='bold')
        ax.text(x + w / 2, y + h * 0.29, sub, ha='center', va='center', fontsize=7.4, color=INK)
    else:
        ax.text(x + w / 2, y + h / 2, title, ha='center', va='center', fontsize=8.6,
                color=INK, fontweight='bold')


def defense(ax, x, y, w, label):
    ax.add_patch(FancyBboxPatch((x, y), w, 0.34, boxstyle='round,pad=0.02,rounding_size=0.06',
                                facecolor='white', edgecolor=DEFENSE, linewidth=1.4))
    ax.text(x + w / 2, y + 0.17, label, ha='center', va='center', fontsize=7.6, color=INK)


def attack(ax, x, y, n, label, ha='left'):
    ax.add_patch(plt.Circle((x, y), 0.17, facecolor=ATTACK, edgecolor='none', zorder=4))
    ax.text(x, y, n, ha='center', va='center', fontsize=7.6, color='white', fontweight='bold', zorder=5)
    dx = 0.26 if ha == 'left' else -0.26
    ax.text(x + dx, y, label, ha=ha, va='center', fontsize=7.4, color=INK, style='italic')


def arrow(ax, a, b, color=INK, style='-|>', ls='-', rad=0.0):
    ax.add_patch(FancyArrowPatch(a, b, arrowstyle=style, mutation_scale=9, color=color,
                                 linewidth=0.9, linestyle=ls,
                                 connectionstyle=f'arc3,rad={rad}'))


def main(out):
    plt.rcParams.update({'font.family': 'serif',
                         'font.serif': ['Times New Roman', 'Times', 'DejaVu Serif']})
    fig, ax = plt.subplots(figsize=(7.0, 5.6))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 8)
    ax.axis('off')

    # User task and final response
    box(ax, 0.2, 6.95, 2.2, 0.75, 'User task', '4 enterprise scenarios')
    box(ax, 7.6, 6.95, 2.2, 0.75, 'Response', 'to the user')

    # Orchestrator loop
    ax.add_patch(FancyBboxPatch((0.2, 2.75), 9.6, 3.75, boxstyle='round,pad=0.02,rounding_size=0.12',
                                facecolor='white', edgecolor=MUTED, linewidth=0.9, linestyle='--'))
    ax.text(3.25, 6.27, 'Orchestrator loop (≤ 15 steps)', fontsize=8, color=MUTED, va='center')

    defense(ax, 0.45, 5.55, 1.9, 'L1 Input screener (task)')
    arrow(ax, (1.3, 6.95), (1.3, 5.92))

    box(ax, 3.2, 4.95, 3.6, 1.0, 'Planner', 'gpt-oss-20b via Groq · temperature 0\n'
        'system prompt: retrieved content is data')
    arrow(ax, (2.35, 5.72), (3.2, 5.55))

    defense(ax, 7.3, 5.45, 2.3, 'L2 Goal verifier (every step)')
    defense(ax, 7.3, 4.95, 2.3, 'L4 HITL gate (write calls)')
    arrow(ax, (6.8, 5.62), (7.3, 5.62))
    arrow(ax, (8.45, 5.45), (8.45, 5.29))

    defense(ax, 7.3, 6.0, 2.3, 'L3 Output validator (final)')
    arrow(ax, (5.0, 5.95), (7.3, 6.17), rad=-0.15)
    arrow(ax, (8.7, 6.34), (8.7, 6.95))

    # Context with delimited tool output
    box(ax, 3.2, 3.0, 3.6, 0.95, 'Context', 'tool output wrapped in untrusted-content delimiters')
    arrow(ax, (5.0, 3.95), (5.0, 4.95))
    defense(ax, 0.45, 3.3, 2.3, 'L1 Input screener (tool output)')
    arrow(ax, (2.75, 3.47), (3.2, 3.47))

    # Tools
    arrow(ax, (8.45, 4.95), (8.45, 2.05))
    box(ax, 0.2, 0.3, 2.9, 1.15, 'Retrieval', 'ChromaDB · MiniLM embeddings\nenterprise document corpus')
    box(ax, 3.55, 0.3, 2.9, 1.15, 'Code execution', 'RestrictedPython sandbox')
    box(ax, 6.9, 0.3, 2.9, 1.15, 'API call', 'httpx · mock HR API\nwrite methods need hitl_approved')
    defense(ax, 6.9, 1.6, 2.9, 'Domain allowlist (layered only)')
    ax.plot([1.65, 8.35], [1.95, 1.95], color=INK, linewidth=0.9)
    for x in (1.65, 5.0):
        arrow(ax, (x, 1.95), (x, 1.45))
    arrow(ax, (8.35, 1.95), (8.35, 1.94))
    arrow(ax, (0.6, 1.45), (0.6, 3.3), rad=0.0)
    ax.text(0.68, 2.4, 'tool\noutput', fontsize=7, color=MUTED, va='center')

    # Attack entry points
    attack(ax, 1.55, 2.4, '1', 'Indirect injection:\npoisoned document, API\nfield or tool metadata')
    attack(ax, 4.0, 2.4, '2', 'Goal hijacking: response\npoisoned at step 1/3/5/8')
    attack(ax, 6.3, 2.4, '3', 'Cascade: induced tool\nfailure, depth 1/2/5/10')
    attack(ax, 3.05, 4.55, '4', 'Tool poisoning:\npoisoned tool\ndescriptions', ha='right')
    arrow(ax, (3.22, 4.55), (3.5, 4.95), color=ATTACK)

    # Legend
    ax.add_patch(FancyBboxPatch((3.3, 7.17), 0.35, 0.22, boxstyle='round,pad=0.01',
                                facecolor='white', edgecolor=DEFENSE, linewidth=1.4))
    ax.text(3.75, 7.28, 'defense layer (layered profile)', fontsize=7.4, va='center', color=INK)
    ax.add_patch(plt.Circle((3.48, 6.92), 0.11, facecolor=ATTACK, edgecolor='none'))
    ax.text(3.75, 6.92, 'attack entry point', fontsize=7.4, va='center', color=INK)

    fig.tight_layout(pad=0.2)
    fig.savefig(out, dpi=300, facecolor='white')


if __name__ == '__main__':
    main(sys.argv[1])
