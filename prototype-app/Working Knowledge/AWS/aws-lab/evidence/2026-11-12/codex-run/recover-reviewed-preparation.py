from pathlib import Path
import json, shlex, re, ast

BASE = Path('/private/tmp/scoutgrid-postmerge-artifacts')
ROOT = BASE / 'access-review-20261112'
ROOT.mkdir(mode=0o700, exist_ok=True)
older = json.loads((BASE/'recovered-older-preparation.json').read_text())
commands = json.loads((BASE/'recovered-preparation-commands.json').read_text())
plan_cmd = next(x for x in older if x['id']=='exec-c34c62ff-5ac6-4cb9-8ab5-dd63580acf5e')
plan = shlex.split(plan_cmd['command'])[-1].split("<<'PY'\n",1)[1].split('\nPY\n',1)[0]
(ROOT/'build-plan-policy.py').write_text(plan)
cmd = shlex.split(next(x for x in older if x['id']=='exec-fa0121de-19ba-4016-9a5d-6d5eab395688')['command'])[-1]
block = cmd.split("<<'PY'\n",1)[1].split('\nPY',1)[0]
exec(compile(block, '<recovered offline plan edit>', 'exec'))
initial = (BASE/'recovered-command-text').glob('01-*')
text = next(initial).read_text().split("<<'PY'\n",1)[1].split('\nPY\n',1)[0]
(ROOT/'build-execution-drafts.py').write_text(text)
# Replay only the inspected local text edits; never replay shell commands,
# provider operations, synthetic fixture generation, or historical grants.
for index in [2,3,4,5,7,8,9,10]:
    cmd = next((BASE/'recovered-command-text').glob(f'{index:02d}-*')).read_text()
    block = cmd.split("<<'PY'\n",1)[1].split('\nPY',1)[0]
    if index == 9:
        block = block[block.index("p=Path('/private/tmp/scoutgrid-postmerge-artifacts/access-review-20261112/build-execution-drafts.py')"):]
    stop = block.index('p.write_text(s)') + len('p.write_text(s)')
    block = block[:stop]
    exec(compile(block, '<recovered offline execution edit>', 'exec'))
# Chat history redacts even these non-secret ARN name fragments. Reconstruct
# only the reviewed resource names from the owner handoff and live metadata.
for name in ['build-plan-policy.py','build-execution-drafts.py']:
    p=ROOT/name
    s=p.read_text().replace('secret:[REDACTED_SECRET]'+"'+n", 'secret:scoutgrid-lab/'+"'+n")
    if name=='build-execution-drafts.py':
        needle="arn('secretsmanager','secret:[REDACTED_SECRET]')"
        for token in ['RENDER_CAPTURED_RUNTIME_SECRET','RENDER_CAPTURED_APPLICATION_SECRET','RENDER_CAPTURED_ENROLLMENT_SECRET']:
            s=s.replace(needle, "arn('secretsmanager','secret:"+token+"')", 1)
    ast.parse(s)
    p.write_text(s)
doc=next((BASE/'recovered-command-text').glob('11-*')).read_text().split("<<'EOF'\n",1)[1].split('\nEOF\n',1)[0]
(ROOT/'ROLE_AND_CLEANUP_REVIEW.md').write_text(doc+'\n')
print('Recovered reviewed offline builder text and disposition. No cloud mutation.')
