#!/bin/zsh
# Resume the full evaluation from checkpoint. Run daily during development.
# session-scoped scheduled task; a no-op once every trial is checkpointed.
# `resume_run.sh --check` only prints the checkpoint count.

# Repo root: the parent of this script's directory, wherever it is cloned.
REPO="${0:A:h:h}"
# Checkpoint lines when complete: the 704 trial slots configured in
# configs/attack_config.yaml. The published dataset holds 740 (36 extra
# benign-baseline trials from an earlier config), which also counts as done.
# Override with RESUME_TOTAL if you change the trial counts.
TOTAL=${RESUME_TOTAL:-704}

cd "$REPO" || { echo "$(date '+%F %T') cannot cd to $REPO"; exit 1; }

ckpt=data/results/trials_checkpoint.jsonl
done_count=0
[[ -f "$ckpt" ]] && done_count=$(wc -l < "$ckpt" | tr -d ' ')
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
