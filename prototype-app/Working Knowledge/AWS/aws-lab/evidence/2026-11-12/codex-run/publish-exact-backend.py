#!/usr/bin/env python3
"""Publish the approved retained archive; keep credentials only in process memory."""
import base64, datetime, hashlib, json, os, pathlib, subprocess, tempfile
import boto3

ACCOUNT='736486260824'
REGION='ap-southeast-2'
SOURCE='0ae3de9f4e4f7b1f784622d31656f30a89499043'
CONFIG='sha256:0186580fbd1634f2ae45bec3eff29e872b4296c817d76836d5f23d2e335e1b98'
ARCHIVE='d73f11cb3ac4be0bb51164bc263b179f8fae817f7e971ae23b0bc6336d7a02bd'
REPO='scoutgrid-lab-backend'
TAG='candidate-0ae3de9-43137000995'

def main():
    home=pathlib.Path.home()
    clock=json.loads((home/'scoutgrid-application-clock-20261112.json').read_text())
    assert datetime.datetime.now(datetime.timezone.utc)<datetime.datetime.fromisoformat(clock['cleanup_start_no_later_utc'])
    archive=home/'image.tar.gz'
    assert hashlib.file_digest(archive.open('rb'),'sha256').hexdigest()==ARCHIVE
    base=boto3.Session(region_name=REGION)
    sts=base.client('sts');assert sts.get_caller_identity()['Account']==ACCOUNT
    c=sts.assume_role(RoleArn=f'arn:aws:iam::{ACCOUNT}:role/ScoutGridSydneyLabImagePublish',RoleSessionName='sg-exact-publish-20261112',DurationSeconds=900)['Credentials']
    s=boto3.Session(region_name=REGION,aws_access_key_id=c['AccessKeyId'],aws_secret_access_key=c['SecretAccessKey'],aws_session_token=c['SessionToken'])
    caller=s.client('sts').get_caller_identity()['Arn'];assert ':assumed-role/ScoutGridSydneyLabImagePublish/' in caller
    ecr=s.client('ecr')
    repo=ecr.describe_repositories(repositoryNames=[REPO])['repositories'][0]
    assert repo['registryId']==ACCOUNT and repo['imageTagMutability']=='IMMUTABLE' and repo['imageScanningConfiguration']['scanOnPush']
    registry=f'{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com'
    target=f'{registry}/{REPO}:{TAG}'
    try:
        details=ecr.describe_images(repositoryName=REPO,imageIds=[{'imageTag':TAG}])['imageDetails'];assert len(details)==1
        already=True
    except ecr.exceptions.ImageNotFoundException:
        already=False
    if not already:
        subprocess.run(['docker','info','--format','{{.ServerVersion}}'],check=True)
        subprocess.run(['docker','load','--input',str(archive)],check=True)
        subprocess.run(['python3',str(home/'scoutgrid-preflight-tools/verify-aws-backend-archive.py'),str(archive),str(home/'scoutgrid-preflight-tools/backend-manifest.json'),'--source-sha',SOURCE,'--loaded-image'],check=True)
        local=f'scoutgrid-aws-backend:{SOURCE}'
        inspect=json.loads(subprocess.check_output(['docker','image','inspect',local],text=True))[0]
        assert inspect['Os']=='linux' and inspect['Architecture']=='amd64' and inspect['Config']['User']=='vulnwatch:vulnwatch'
        auth=ecr.get_authorization_token(registryIds=[ACCOUNT])['authorizationData'][0]
        assert auth['proxyEndpoint']=='https://'+registry
        username,password=base64.b64decode(auth['authorizationToken']).decode().split(':',1);assert username=='AWS'
        with tempfile.TemporaryDirectory(prefix='sg-ecr-auth-') as directory:
            os.chmod(directory,0o700);env=os.environ.copy();env['DOCKER_CONFIG']=directory
            login=subprocess.run(['docker','login','--username','AWS','--password-stdin',registry],input=password,text=True,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            assert login.returncode==0,'Docker login failed; token withheld'
            del password,auth
            subprocess.run(['docker','tag',local,target],check=True,env=env)
            subprocess.run(['docker','push',target],check=True,env=env)
        details=ecr.describe_images(repositoryName=REPO,imageIds=[{'imageTag':TAG}])['imageDetails'];assert len(details)==1
    image=ecr.batch_get_image(repositoryName=REPO,imageIds=[{'imageTag':TAG}])
    assert not image.get('failures') and len(image['images'])==1
    manifest=image['images'][0]['imageManifest'];document=json.loads(manifest)
    assert document['config']['digest']==CONFIG
    digest=image['images'][0]['imageId']['imageDigest']
    assert digest==details[0]['imageDigest'] and digest=='sha256:'+hashlib.sha256(manifest.encode()).hexdigest()
    result={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'caller':caller,'source_sha':SOURCE,'archive_sha256':ARCHIVE,'configuration_digest':CONFIG,'registry_digest':digest,'repository_uri':repo['repositoryUri'],'tag':TAG,'reconciled_existing_tag':already,'secret_values_retrieved':False}
    output=home/'scoutgrid-published-backend-20261112.json';output.write_text(json.dumps(result,indent=2)+'\n');output.chmod(0o600)
    print('EXACT_BACKEND_PUBLICATION',json.dumps(result),flush=True)

if __name__=='__main__':main()
