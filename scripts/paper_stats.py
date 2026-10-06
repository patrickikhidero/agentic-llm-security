"""Reproduce every statistic reported in the paper from the checkpoint files.

Reads data/results/trials_checkpoint.jsonl (final, 740 records) and, for the
pooled utility of the two injection classes, the first collection kept in
trials_checkpoint.jsonl.pre-scorer-fix.bak (FINDINGS.md §5.5).

Run from the repo root: ./venv/bin/python scripts/paper_stats.py [--json out.json]

Conventions: Wilson 95% intervals for proportions, two-sided Fisher exact
tests for baseline-vs-layered comparisons, and a 95% log-scale (Katz)
interval for the utility ratio TCR_layered / TCR_baseline.
"""
import argparse
import collections
import json
import math
import re
import sys
from pathlib import Path

from scipy.stats import fisher_exact

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.evaluation.runner import (GOAL_HIJACK_COMBOS,  # noqa: E402
                                   TOOL_POISONING_COMBOS)

RESULTS = Path('data/results')
FINAL = RESULTS / 'trials_checkpoint.jsonl'
FIRST = RESULTS / 'trials_checkpoint.jsonl.pre-scorer-fix.bak'
CLASSES = ['indirect_injection', 'goal_hijacking', 'cascade_exploit', 'tool_poisoning']
POOLED = {'indirect_injection', 'goal_hijacking'}   # §5.5: utility pooled over both collections


def load(path):
    return [json.loads(line) for line in open(path)]


def wilson(k, n, z=1.959964):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    c = (p + z * z / (2 * n)) / (1 + z * z / n)
    w = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (max(0.0, c - w), min(1.0, c + w))


def fisher(k1, n1, k2, n2):
    return fisher_exact([[k1, n1 - k1], [k2, n2 - k2]])[1]


def ratio_ci(kl, nl, kb, nb, z=1.959964):
    r = (kl / nl) / (kb / nb)
    se = math.sqrt(1 / kl - 1 / nl + 1 / kb - 1 / nb)
    return r, r * math.exp(-z * se), r * math.exp(z * se)


def idx(trial):
    return int(trial['trial_id'].rsplit('_', 1)[1])


def mounted(trial):
    """Whether the attack payload actually reached the agent.

    Injection classes persist a `mounted` field; cascade trials record it in
    their notes. Tool poisoning is always mounted (the registry is poisoned
    before the first step).
    """
    if 'mounted' in trial:
        return bool(trial['mounted'])
    m = re.search(r'mounted=(True|False)', trial.get('notes', ''))
    if m:
        return m.group(1) == 'True'
    return trial['attack_class'] == 'tool_poisoning'


def cell(rows, cls, prof):
    return [r for r in rows if r['attack_class'] == cls and r['defense_profile'] == prof]


def pct(k, n):
    return round(100 * k / n, 1) if n else None


def ci_pct(k, n):
    lo, hi = wilson(k, n)
    return [round(100 * lo, 1), round(100 * hi, 1)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--json', help='write all statistics to this file')
    args = ap.parse_args()

    final, first = load(FINAL), load(FIRST)
    ids = [r['trial_id'] for r in final]
    assert len(ids) == len(set(ids)), 'duplicate trial ids in checkpoint'
    out = {'n_records': len(final), 'table1': {}, 'detail': {}}

    # ── Table 1 ────────────────────────────────────────────────────────────────
    for cls in CLASSES:
        b, l = cell(final, cls, 'baseline'), cell(final, cls, 'layered')
        sb, sl = sum(r['attack_success'] for r in b), sum(r['attack_success'] for r in l)
        mb, ml = [r for r in b if mounted(r)], [r for r in l if mounted(r)]
        smb, sml = sum(r['attack_success'] for r in mb), sum(r['attack_success'] for r in ml)
        # TCR and utility: pooled over both collections for the injection classes
        tb, tl = list(b), list(l)
        if cls in POOLED:
            tb += cell(first, cls, 'baseline')
            tl += cell(first, cls, 'layered')
        kb, kl = sum(r['task_completed'] for r in tb), sum(r['task_completed'] for r in tl)
        u, ulo, uhi = ratio_ci(kl, len(tl), kb, len(tb))
        out['table1'][cls] = {
            'asr_baseline': [sb, len(b), pct(sb, len(b)), ci_pct(sb, len(b))],
            'asr_layered': [sl, len(l), pct(sl, len(l)), ci_pct(sl, len(l))],
            'reduction_pp': round(pct(sb, len(b)) - pct(sl, len(l)), 1),
            'fisher_p': fisher(sb, len(b), sl, len(l)),
            'mounted': [len(mb), len(ml)],
            'asr_mounted_baseline': [smb, len(mb), ci_pct(smb, len(mb))],
            'asr_mounted_layered': [sml, len(ml), ci_pct(sml, len(ml))],
            'fisher_p_mounted': fisher(smb, len(mb), sml, len(ml)) if mb and ml else None,
            'tcr_baseline': [kb, len(tb), pct(kb, len(tb))],
            'tcr_layered': [kl, len(tl), pct(kl, len(tl))],
            'utility': [round(u, 3), round(ulo, 3), round(uhi, 3)],
            'pooled': cls in POOLED,
            'halted_layered': sum(r['blocked_by_defense'] for r in l),
        }
        if cls in POOLED:
            per = []
            for rows in (first, final):
                cb, cl = cell(rows, cls, 'baseline'), cell(rows, cls, 'layered')
                per.append(round((sum(r['task_completed'] for r in cl) / len(cl))
                                 / (sum(r['task_completed'] for r in cb) / len(cb)), 3))
            out['table1'][cls]['utility_per_collection'] = per

    # Pooled indirect vs goal_hijacking layered TCR
    t = out['table1']
    a, g = t['indirect_injection']['tcr_layered'], t['goal_hijacking']['tcr_layered']
    out['detail']['layered_tcr_indirect_vs_goal_p'] = fisher(a[0], a[1], g[0], g[1])

    # ── Benign: TCR and false-positive rate per layer ──────────────────────────
    bb, bl = cell(final, 'benign', 'baseline'), cell(final, 'benign', 'layered')
    fp = collections.Counter()
    for r in bl:
        for layer in {e.get('defense') for e in r['defense_events']}:
            fp[layer] += 1
    out['detail']['benign'] = {
        'tcr_baseline': [sum(r['task_completed'] for r in bb), len(bb)],
        'tcr_layered': [sum(r['task_completed'] for r in bl), len(bl)],
        'fpr_by_layer': {k: [v, len(bl)] for k, v in sorted(fp.items())},
        'fp_by_task': dict(collections.Counter(r['task_scenario'] for r in bl if r['defense_events'])),
    }

    # ── Defense events in layered attack trials ────────────────────────────────
    ev = {}
    for cls in CLASSES:
        c = collections.Counter()
        halts = collections.Counter()
        for r in cell(final, cls, 'layered'):
            for e in r['defense_events']:
                c[f"{e.get('defense')}:{e.get('event')}"] += 1
            if r['blocked_by_defense'] and r['defense_events']:
                halts[r['defense_events'][-1].get('defense')] += 1
        ev[cls] = {'events': dict(c), 'halting_layer': dict(halts)}
    out['detail']['layered_defense_events'] = ev

    # ── ASR by task scenario (baseline) ────────────────────────────────────────
    by_task = {}
    for cls in CLASSES:
        c = collections.defaultdict(lambda: [0, 0])
        for r in cell(final, cls, 'baseline'):
            c[r['task_scenario']][0] += r['attack_success']
            c[r['task_scenario']][1] += 1
        by_task[cls] = dict(c)
    out['detail']['baseline_asr_by_task'] = by_task

    # ── Goal hijacking by injection step (RQ4) ─────────────────────────────────
    gh = {}
    for prof in ('baseline', 'layered'):
        c = collections.defaultdict(lambda: [0, 0, 0])   # successes, mounted, trials
        for r in cell(final, 'goal_hijacking', prof):
            step = GOAL_HIJACK_COMBOS[idx(r) % len(GOAL_HIJACK_COMBOS)][0]
            c[step][0] += r['attack_success']
            c[step][1] += mounted(r)
            c[step][2] += 1
        gh[prof] = {str(k): v for k, v in sorted(c.items())}
    out['detail']['goal_hijacking_by_step'] = gh

    # ── Cascade mounting by depth ──────────────────────────────────────────────
    cd = collections.defaultdict(lambda: [0, 0])
    steps = collections.Counter()
    for r in cell(final, 'cascade_exploit', 'baseline') + cell(final, 'cascade_exploit', 'layered'):
        m = re.search(r'depth=(\d+)', r.get('notes', ''))
        if m:
            cd[int(m.group(1))][0] += mounted(r)
            cd[int(m.group(1))][1] += 1
    for r in cell(final, 'cascade_exploit', 'baseline'):
        steps[r['steps_taken']] += 1
    out['detail']['cascade_mounted_by_depth'] = {str(k): v for k, v in sorted(cd.items())}
    out['detail']['cascade_baseline_steps_taken'] = dict(sorted(steps.items()))

    # ── Tool poisoning by variant ──────────────────────────────────────────────
    tp = {}
    for prof in ('baseline', 'layered'):
        c = collections.defaultdict(lambda: [0, 0, 0])   # successes, halted, trials
        for r in cell(final, 'tool_poisoning', prof):
            strat, tool = TOOL_POISONING_COMBOS[idx(r) % len(TOOL_POISONING_COMBOS)]
            k = f'{strat}/{tool}'
            c[k][0] += r['attack_success']
            c[k][1] += r['blocked_by_defense']
            c[k][2] += 1
        tp[prof] = dict(c)
    out['detail']['tool_poisoning_by_variant'] = tp

    # ── Write-gate self-approval (injection classes, baseline successes) ───────
    sa = collections.Counter()
    for cls in POOLED:
        for r in cell(final, cls, 'baseline'):
            if not r['attack_success']:
                continue
            posts = [c for c in r.get('tool_calls') or []
                     if c.get('tool') == 'api_call'
                     and str((c.get('input') or {}).get('method', '')).upper() == 'POST']
            if not posts:
                sa['no_post'] += 1
            elif posts[0]['input'].get('hitl_approved'):
                sa['self_approved_first_try'] += 1
            elif any(c['input'].get('hitl_approved') for c in posts):
                sa['self_approved_after_rejection'] += 1
            else:
                sa['never_approved'] += 1
    out['detail']['write_gate_self_approval'] = dict(sa)

    # ── Print ──────────────────────────────────────────────────────────────────
    print(f"records: {out['n_records']}")
    print(f"{'class':20} {'ASR b':>22} {'ASR l':>20} {'p':>9} {'TCR b':>14} {'TCR l':>14} {'util (95% CI)':>22}")
    for cls, v in t.items():
        ab, al = v['asr_baseline'], v['asr_layered']
        print(f"{cls:20} {ab[0]:>3}/{ab[1]} {ab[2]:>5}% {str(ab[3]):>12} "
              f"{al[0]:>3}/{al[1]} {al[2]:>5}% {str(al[3]):>10} {v['fisher_p']:9.2e} "
              f"{v['tcr_baseline'][0]:>3}/{v['tcr_baseline'][1]:<3} {v['tcr_baseline'][2]:>5}% "
              f"{v['tcr_layered'][0]:>3}/{v['tcr_layered'][1]:<3} {v['tcr_layered'][2]:>5}% "
              f"{v['utility'][0]:.3f} ({v['utility'][1]:.3f}-{v['utility'][2]:.3f}){' pooled' if v['pooled'] else ''}")
    print(json.dumps(out['detail'], indent=1))
    if args.json:
        Path(args.json).write_text(json.dumps(out, indent=1))


if __name__ == '__main__':
    main()
