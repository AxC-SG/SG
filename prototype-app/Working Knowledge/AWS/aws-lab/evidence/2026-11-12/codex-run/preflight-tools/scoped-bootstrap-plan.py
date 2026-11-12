#!/usr/bin/env python3
"""Create and review only a saved bootstrap plan, never apply it."""
import boto3
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path('/tmp/scoutgrid-plan-0ae3de9')
SOURCE = '0ae3de9f4e4f7b1f784622d31656f30a89499043'
TARGETS = ['aws_kms_key.database', 'aws_kms_key.objects',
    'aws_cognito_user_pool.humans', 'aws_amplify_app.frontend',
    'aws_s3_bucket.artifacts', 'aws_s3_bucket_public_access_block.artifacts',
    'aws_s3_bucket_ownership_controls.artifacts', 'aws_s3_bucket_versioning.artifacts',
    'aws_s3_bucket_server_side_encryption_configuration.artifacts',
    'aws_s3_bucket_cors_configuration.imports', 'aws_s3_bucket_policy.artifacts']


def main():
    manifest = json.loads((ROOT / 'source-manifest.json').read_text())
    assert manifest['source_sha'] == SOURCE
    for rel, expected in manifest['files'].items():
        assert hashlib.sha256((ROOT / rel).read_bytes()).hexdigest() == expected, rel
    sts = boto3.client('sts', region_name='ap-southeast-2')
    assert sts.get_caller_identity()['Account'] == '736486260824'
    c = sts.assume_role(RoleArn='arn:aws:iam::736486260824:role/ScoutGridSydneyLabBootstrap',
        RoleSessionName='sg-bootstrap-plan-20261112', DurationSeconds=3600)['Credentials']
    session = boto3.Session(region_name='ap-southeast-2',
        aws_access_key_id=c['AccessKeyId'], aws_secret_access_key=c['SecretAccessKey'],
        aws_session_token=c['SessionToken'])
    who = session.client('sts').get_caller_identity()
    assert ':assumed-role/ScoutGridSydneyLabBootstrap/' in who['Arn']
    env = os.environ.copy()
    env.update(AWS_ACCESS_KEY_ID=c['AccessKeyId'], AWS_SECRET_ACCESS_KEY=c['SecretAccessKey'],
        AWS_SESSION_TOKEN=c['SessionToken'], AWS_REGION='ap-southeast-2',
        AWS_DEFAULT_REGION='ap-southeast-2', TF_IN_AUTOMATION='1')
    for key in ['AWS_PROFILE', 'AWS_DEFAULT_PROFILE']:
        env.pop(key, None)
    root = ROOT / 'standard'
    command = [str(ROOT / 'terraform'), 'plan', '-input=false', '-no-color',
        '-lock-timeout=30s', '-var-file=sydney-lab.foundation.tfvars', '-out=bootstrap.tfplan']
    with (root / 'bootstrap-plan.log').open('w') as log:
        run = subprocess.run(command + ['-target=' + x for x in TARGETS],
            cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
    if run.returncode:
        print((root / 'bootstrap-plan.log').read_text()[-4000:])
        raise SystemExit(run.returncode)
    plan = json.loads(subprocess.check_output([str(ROOT / 'terraform'), 'show', '-json',
        'bootstrap.tfplan'], cwd=root, env=env, text=True))
    changes = [x for x in plan['resource_changes'] if x['change']['actions'] != ['no-op']]
    assert len(changes) == 17
    assert all(x['change']['actions'] == ['create'] for x in changes)
    assert all(x['address'].split('[')[0] in TARGETS for x in changes)
    summary = {'planned_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'caller': who['Arn'], 'source_sha': SOURCE, 'source_manifest_verified': True,
        'plan_sha256': hashlib.sha256((root / 'bootstrap.tfplan').read_bytes()).hexdigest(),
        'resources': [{'address': x['address'], 'actions': x['change']['actions'],
            'after': x['change']['after'], 'after_unknown': x['change']['after_unknown']}
            for x in changes], 'applied': False}
    (root / 'bootstrap-plan-review.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k != 'resources'}, sort_keys=True))
    print(json.dumps([x['address'] for x in changes]))


if __name__ == '__main__':
    main()
