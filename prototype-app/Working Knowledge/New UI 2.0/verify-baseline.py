#!/usr/bin/env python3
"""Read-only comparison against the UI 2.0 behavior baseline."""
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repo', type=Path, required=True, help='Repository root containing prototype-app/')
args = parser.parse_args()
repo = args.repo.expanduser().resolve()
manifest = json.loads((Path(__file__).resolve().parent / 'BEHAVIOR_BASELINE_2026-10-24.json').read_text())
frontend = repo / 'prototype-app/frontend'
results = {'matched': [], 'changed': [], 'missing': [], 'additional_missing': []}
for relative, expected in manifest['frontendSourceSha256'].items():
    path = frontend / relative
    if not path.is_file():
        results['missing'].append(relative)
    elif hashlib.sha256(path.read_bytes()).hexdigest() == expected:
        results['matched'].append(relative)
    else:
        results['changed'].append(relative)
additional = [
    'prototype-app/CLAUDE.md',
    'prototype-app/frontend/CLAUDE.md',
    'prototype-app/frontend/src/components/RouteErrorBoundary.tsx',
    'prototype-app/frontend/src/components/RouteErrorBoundary.test.tsx',
    'prototype-app/frontend/src/features/cve-workbench/components/WorkbenchMain.test.tsx',
    'prototype-app/frontend/src/features/cve-workbench/assessment-helpers.test.ts',
    'prototype-app/frontend/src/pages/FindingsPage.test.tsx',
    'prototype-app/frontend/src/pages/AiFindingsPage.test.tsx',
    'prototype-app/frontend/src/pages/VulnRepoCveAssetsPage.test.tsx',
    '.github/workflows/quality.yml',
]
results['additional_missing'] = [relative for relative in additional if not (repo / relative).is_file()]
print(json.dumps(results, indent=2))
print('Read-only check. Changed files require delta review, not automatic replacement. Hash matches do not establish full application or release readiness.')
raise SystemExit(1 if any(results[key] for key in ['changed', 'missing', 'additional_missing']) else 0)
