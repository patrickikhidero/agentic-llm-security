#!/bin/zsh
# Resume the full evaluation from checkpoint. Run daily by a Claude Code
# session-scoped scheduled task; a no-op once every trial is checkpointed.
# `resume_run.sh --check` only prints the checkpoint count.

REPO="${0:A:h:h}"
# Checkpoint lines when complete: 704 configured slots plus 36 benign-baseline
# trials left over from the earlier 20-per-scenario benign config (which the
# runner's "N/704 trials done" message counts as done).
TOTAL=740

cd "$REPO" || { echo "$(date '+%F %T') cannot cd to $REPO"; exit 1; }

done_count=$(wc -l < data/results/trials_checkpoint.jsonl | tr -d ' ')
echo "$(date '+%F %T') resume_run: ${done_count}/${TOTAL} trials checkpointed"

if [[ "$1" == "--check" ]]; then
  exit 0
fi
if (( done_count >= TOTAL )); then
  echo "$(date '+%F %T') resume_run: all trials done, nothing to run"
  exit 0
fi

exec ./venv/bin/python -m src.evaluation.runner --mode full_eval \
  --config configs/attack_config.yaml >> data/results/run.log 2>&1
