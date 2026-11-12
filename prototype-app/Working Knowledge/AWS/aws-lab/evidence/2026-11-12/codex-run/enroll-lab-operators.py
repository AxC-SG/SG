#!/usr/bin/env python3
"""Enroll the two approved operators without delivery or password disclosure."""
import boto3,datetime,json,os,pathlib,re
ACCOUNT='736486260824';REGION='ap-southeast-2';POOL='ap-southeast-2_fPdRmnVqM'
EMAILS=['scoutgrid.io@gmail.com','scoutgridtenant@gmail.com']
def main():
 h=pathlib.Path.home();out=h/'scoutgrid-operator-enrollment-20261112.json';assert not out.exists(),'Reconcile existing metadata before retry'
 clock=json.loads((h/'scoutgrid-application-clock-20261112.json').read_text());assert datetime.datetime.now(datetime.timezone.utc)<datetime.datetime.fromisoformat(clock['cleanup_start_no_later_utc'])
 base=boto3.Session(region_name=REGION);sts=base.client('sts');assert sts.get_caller_identity()['Account']==ACCOUNT
 c=sts.assume_role(RoleArn=f'arn:aws:iam::{ACCOUNT}:role/ScoutGridSydneyLabIdentity',RoleSessionName='sg-operator-enroll-20261112',DurationSeconds=900)['Credentials']
 s=boto3.Session(region_name=REGION,aws_access_key_id=c['AccessKeyId'],aws_secret_access_key=c['SecretAccessKey'],aws_session_token=c['SessionToken']);who=s.client('sts').get_caller_identity()['Arn'];assert ':assumed-role/ScoutGridSydneyLabIdentity/' in who
 client=s.client('cognito-idp');pool=client.describe_user_pool(UserPoolId=POOL)['UserPool'];assert pool['Name']=='scoutgrid-lab-humans' and pool['MfaConfiguration']=='ON' and pool['DeletionProtection']=='ACTIVE'
 for email in EMAILS:
  try:client.admin_get_user(UserPoolId=POOL,Username=email);raise RuntimeError('Existing user; reconcile before retry')
  except client.exceptions.UserNotFoundException:pass
 result={'pool_id':POOL,'caller':who,'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'message_action':'SUPPRESS','setup_emails_sent':False,'users':[]}
 for email in EMAILS:
  response=client.admin_create_user(UserPoolId=POOL,Username=email,UserAttributes=[{'Name':'email','Value':email},{'Name':'email_verified','Value':'true'}],MessageAction='SUPPRESS',ForceAliasCreation=False)
  created=response['User'];attrs={a['Name']:a['Value'] for a in created['Attributes']};assert attrs['email']==email and re.fullmatch(r'[0-9a-f-]{36}',attrs['sub'])
  result['users'].append({'email':email,'username':created['Username'],'sub':attrs['sub'],'status':created['UserStatus'],'create_request_id':response['ResponseMetadata']['RequestId'],'verified':False})
  with os.fdopen(os.open(out,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600),'w') as f:json.dump(result,f,indent=2);f.flush();os.fsync(f.fileno())
  verified=client.admin_get_user(UserPoolId=POOL,Username=email);v={a['Name']:a['Value'] for a in verified['UserAttributes']};assert v['email']==email and v['sub']==attrs['sub'] and v['email_verified']=='true' and verified['UserStatus']=='FORCE_CHANGE_PASSWORD' and verified['Enabled']
  result['users'][-1]['verified']=True;out.write_text(json.dumps(result,indent=2)+'\n')
 assert len({u['sub'] for u in result['users']})==2
 binding=h/'scoutgrid-application-key-20261112.json';b=json.loads(binding.read_text());b['verified_enrollment_subjects']={u['email']:u['sub'] for u in result['users']};binding.write_text(json.dumps(b,indent=2)+'\n')
 print('VERIFIED_OPERATOR_SUBJECTS',json.dumps(result),flush=True)
if __name__=='__main__':main()
