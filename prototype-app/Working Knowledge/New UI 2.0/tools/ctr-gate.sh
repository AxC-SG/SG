#!/bin/zsh
# Container half of the cleanup gate: e2e:visual and e2e:affected in the pinned Playwright image
# (native arm64 under Podman; x86 emulation crashes Chromium).
#
#   podman machine start
#   GATE_WORK=<scratch dir> AFFECTED_BASE=<commit the changes are measured from> \
#     caffeinate -ims tools/ctr-gate.sh <label>
#   podman machine stop        # before any vitest run
#
# Runs on a copy of the committed tree (git archive HEAD), never the working checkout, with its own
# node_modules volume. Fill $GATE_WORK/npmcache on the host first, in a scratch copy of package.json
# and package-lock.json: npm ci --cache $GATE_WORK/npmcache --os=linux --cpu=arm64 --ignore-scripts
set -u
S=${GATE_WORK:?set GATE_WORK to a scratch directory}
BASE=${AFFECTED_BASE:?set AFFECTED_BASE to the commit the change is measured from}
REPO=${0:A:h:h:h:h:h}
L=$1; O=$S/gate-$L; mkdir -p $O
IMAGE=mcr.microsoft.com/playwright:v1.63.0-noble
cd "$REPO/prototype-app/frontend"
ROUTES=$(node e2e/select-affected.mjs --base $BASE)
echo "$ROUTES" > $O/affected-routes.txt
# Fresh copy of the committed tree in a new folder (no host node_modules, dist or .artifacts).
C=$S/ctr-$L-$(git rev-parse --short HEAD)
mkdir $C || { echo "$C exists; use a new label"; exit 2; }
(cd "$REPO" && git archive HEAD prototype-app/frontend) | tar -x -C $C
echo "copy of $(git rev-parse --short HEAD) in $C"
podman run --rm --arch arm64 --ipc=host \
  -v $C:/work -v $S/npmcache:/npmcache -v sg-ui2-node-modules:/work/prototype-app/frontend/node_modules \
  -v $O:/out \
  -e npm_config_cache=/npmcache -e npm_config_prefer_offline=true -e E2E_PLAYWRIGHT_IMAGE=$IMAGE -e ROUTES="$ROUTES" -e CI=1 \
  -w /work/prototype-app/frontend $IMAGE bash -c '
    set -u; uname -m; node -v
    npm ci --no-audit --no-fund > /out/ctr-npm-ci.log 2>&1; echo "npm ci exit=$?"
    npm run e2e:build > /out/ctr-e2e-build.log 2>&1; echo "e2e:build exit=$?"
    npm run e2e:visual > /out/ctr-e2e-visual.log 2>&1; echo "e2e:visual exit=$?"
    # e2e:affected reruns the visual tests into the same folder; keep the visual results first.
    cp -r e2e/.results /out/ctr-results-visual
    npm run e2e:affected -- --routes "$ROUTES" > /out/ctr-e2e-affected.log 2>&1; echo "e2e:affected exit=$?"
    cp -r e2e/.results /out/ctr-results
  ' 2>&1 | tee $O/ctr-summary.txt
