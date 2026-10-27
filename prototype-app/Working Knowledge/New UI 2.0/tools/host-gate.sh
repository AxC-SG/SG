#!/bin/zsh
# Host half of the cleanup gate. Run under caffeinate with the Podman VM stopped.
#
#   GATE_WORK=<scratch dir> [GATE_BASELINE=<dir with probe-ui2.json, probe-legacy.json, state.json>] \
#     caffeinate -ims tools/host-gate.sh <label>
#
# Logs and a summary go to $GATE_WORK/gate-<label>/. Without GATE_BASELINE the style probes are only
# compared cold-vs-navigation; save a run's probe-*.json and state-new.json (as state.json) to use it
# as the baseline for later runs.
set -u
S=${GATE_WORK:?set GATE_WORK to a scratch directory}
TOOLS=${0:A:h}
FE=${0:A:h:h:h:h}/frontend
L=$1; O=$S/gate-$L; mkdir -p $O; cd "$FE"
sum() { echo "$*" | tee -a $O/summary.txt; }
: > $O/summary.txt
sum "label $L commit $(git rev-parse --short HEAD) node $(node -v) $(date -u +%FT%TZ)"
if podman machine inspect --format '{{.State}}' 2>/dev/null | grep -qi running; then sum "ABORT podman VM is running"; exit 3; fi
sum "podman VM: $(podman machine inspect --format '{{.State}}' 2>/dev/null)"
run() { local n=$1; shift; "$@" > $O/$n.log 2>&1; local c=$?; sum "$n exit=$c"; return $c; }
run lint npm run lint; grep -E "problems?|✖" $O/lint.log | tail -1 | sed 's/^/  /' | tee -a $O/summary.txt
run typecheck npm run typecheck
run coverage npm run test:coverage
cp coverage/coverage-summary.json $O/coverage-summary.json
grep -E "Test Files|Tests |skipped|failed" $O/coverage.log | tail -3 | sed 's/^/  /' | tee -a $O/summary.txt
node -e "const t=require('./coverage/coverage-summary.json').total;for(const k of ['lines','statements','functions','branches'])console.log('  '+k,t[k].covered+'/'+t[k].total,t[k].pct+'%')" | tee -a $O/summary.txt
grep -iE "threshold|ERROR: Coverage" $O/coverage.log | head -4 | sed 's/^/  /' | tee -a $O/summary.txt
# Bundle method recorded in the ledger (startingNumbers.bundle): sum over dist/**, gzip level 9.
bundle() { python3 - "$1" <<'EOF' | tee -a $O/summary.txt
import gzip,pathlib,sys
for ext in ('css','js'):
  fs=sorted(pathlib.Path('dist').rglob('*.'+ext)); raw=sum(f.stat().st_size for f in fs); gz=sum(len(gzip.compress(f.read_bytes(),9)) for f in fs)
  print(f"  {sys.argv[1]} {ext}: {len(fs)} files {raw} raw / {gz} gzip")
EOF
}
VITE_UI_VERSION=2 run build-ui2 npm run build; bundle ui2
VITE_UI_VERSION= run build-ui1 npm run build; bundle ui1
run e2e-build npm run e2e:build; grep "boundary" $O/e2e-build.log | sed 's/^/  /' | tee -a $O/summary.txt
run e2e-journeys npm run e2e:journeys
grep -E "passed|failed|skipped|known|new" $O/e2e-journeys.log | grep -iE "total|summary|journey:|passed" | tail -16 | sed 's/^/  /' >> $O/summary.txt
for v in ui2 legacy; do
  node $TOOLS/style-probe.mjs "$FE" $v $O/probe-$v.json > $O/probe-$v.log 2>&1; sum "probe-$v exit=$?"
  if [ -n "${GATE_BASELINE:-}" ]; then
    node $TOOLS/probe-compare.mjs diff $GATE_BASELINE/probe-$v.json $O/probe-$v.json > $O/probe-diff-$v.txt; tail -1 $O/probe-diff-$v.txt | sed 's/^/  /' | tee -a $O/summary.txt
  fi
  node $TOOLS/probe-compare.mjs self $O/probe-$v.json > $O/probe-self-$v.txt; grep -E "comparisons" $O/probe-self-$v.txt | cut -c1-120 | sed 's/^/  /' | tee -a $O/summary.txt
done
node $TOOLS/state-check.mjs "$FE" "$FE/e2e/.artifacts/ui2" 5196 $O/state-new.json > $O/state-new.log 2>&1; sum "state-check exit=$?"
if [ -n "${GATE_BASELINE:-}" ]; then
  if cmp -s $GATE_BASELINE/state.json $O/state-new.json; then sum "  state-check identical to baseline"; else sum "  state-check DIFFERS from baseline"; fi
fi
sum "done $(date -u +%FT%TZ)"
