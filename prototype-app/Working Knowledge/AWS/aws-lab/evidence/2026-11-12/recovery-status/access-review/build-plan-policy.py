"""Prepare an unattached read/lock profile for the exact Sydney Terraform root."""
from pathlib import Path
import json, fnmatch
root=Path(__file__).resolve().parent
account,region='736486260824','ap-southeast-2'
bucket=f'arn:aws:s3:::scoutgrid-lab-tfstate-{account}-{region}'
state=bucket+'/standard/lab/terraform.tfstate'
statements=[]
def add(sid,service,actions,resource='*',regional=True,condition=None):
 item={'Sid':sid,'Effect':'Allow','Action':[service+':'+a for a in actions.split()],'Resource':resource}
 cond={'StringEquals':{'aws:RequestedRegion':region}} if regional else {}
 if condition:
  for op,values in condition.items():cond.setdefault(op,{}).update(values)
 if cond:item['Condition']=cond
 statements.append(item)
def arn(service,suffix):return f'arn:aws:{service}:{region}:{account}:{suffix}'
add('ReadExactStateBucket','s3','GetBucketLocation ListBucket',bucket,False)
add('ReadExactState','s3','GetObject',state,False)
add('ManageOnlyExactStateLock','s3','GetObject PutObject DeleteObject',state+'.tflock',False)
add('UseStateKeyOnlyThroughS3','kms','Decrypt GenerateDataKey',arn('kms','key/2731031f-d79e-4db9-afe6-94fb01cba15a'),condition={'StringEquals':{'kms:ViaService':f's3.{region}.amazonaws.com','kms:CallerAccount':account,'kms:EncryptionContext:aws:s3:arn':bucket}})
add('ReadSydneyNetworkMetadata','ec2','DescribeAddresses DescribeAddressesAttribute DescribeAvailabilityZones DescribeInternetGateways DescribeManagedPrefixLists DescribeNatGateways DescribeNetworkAcls DescribeNetworkInterfaces DescribePrefixLists DescribeRouteTables DescribeSecurityGroups DescribeSecurityGroupRules DescribeSubnets DescribeVpcAttribute DescribeVpcEndpoints DescribeVpcEndpointServices DescribeVpcs')
add('ReadSydneyRdsProviderMetadata','rds','DescribeDBInstances DescribeDBEngineVersions DescribeDBParameterGroups DescribeDBParameters DescribeDBSubnetGroups DescribeDBSnapshots DescribeDBInstanceAutomatedBackups')
add('ReadNamedDatabaseTags','rds','ListTagsForResource',[arn('rds','db:scoutgrid-lab'),arn('rds','pg:scoutgrid-lab-postgres16'),arn('rds','subgrp:scoutgrid-lab')])
add('ReadFreshLabKeyMetadata','kms','DescribeKey GetKeyPolicy GetKeyRotationStatus ListResourceTags',arn('kms','key/*'),condition={'StringEquals':{'aws:ResourceTag/Application':'ScoutGrid','aws:ResourceTag/Environment':'lab'}})
artifacts=[f'arn:aws:s3:::scoutgrid-lab-{account}-{kind}' for kind in ['imports','exports']]
add('ReadNamedLabBucketMetadata','s3','ListBucket GetBucketLocation GetBucketPolicy GetBucketAcl GetBucketCORS GetBucketVersioning GetAccelerateConfiguration GetBucketRequestPayment GetBucketLogging GetLifecycleConfiguration GetReplicationConfiguration GetEncryptionConfiguration GetBucketObjectLockConfiguration GetBucketPublicAccessBlock GetBucketOwnershipControls GetBucketTagging',artifacts,False,{'StringEquals':{'s3:ResourceAccount':account}})
add('ReadSydneyPoolMetadata','cognito-idp','DescribeUserPool GetUserPoolMfaConfig ListTagsForResource DescribeResourceServer DescribeUserPoolClient ListUserPoolClients DescribeManagedLoginBranding DescribeManagedLoginBrandingByClient',arn('cognito-idp','userpool/*'))
add('LocateSydneyPoolAndDomain','cognito-idp','ListUserPools DescribeUserPoolDomain')
add('ReadSydneyFrontendMetadata','amplify','GetApp GetBranch GetDomainAssociation ListDomainAssociations ListTagsForResource',arn('amplify','apps/*'))
add('ReadNamedRepositoryMetadata','ecr','DescribeRepositories DescribeImages ListImages ListTagsForResource',arn('ecr','repository/scoutgrid-lab-backend'))
add('ReadLabEcsMetadata','ecs','DescribeClusters DescribeServices DescribeTasks ListTagsForResource',[arn('ecs','cluster/scoutgrid-lab'),arn('ecs','service/scoutgrid-lab/*'),arn('ecs','task/scoutgrid-lab/*')])
add('ReadTaskDefinitionMetadata','ecs','DescribeTaskDefinition')
add('ListOnlyLabClusterServicesAndTasks','ecs','ListServices ListTasks',condition={'ArnEquals':{'ecs:cluster':arn('ecs','cluster/scoutgrid-lab')}})
add('ReadSydneyEcsLists','ecs','ListClusters ListTaskDefinitions')
add('ReadExactRuntimeRoleMetadata','iam','GetRole GetRolePolicy ListRolePolicies ListAttachedRolePolicies',[f'arn:aws:iam::{account}:role/scoutgrid-lab-{name}' for name in ['api-execution','worker-execution','migrator-execution','api-task','worker-task']],False)
add('ReadSydneyAlbProviderMetadata','elasticloadbalancing','DescribeLoadBalancers DescribeLoadBalancerAttributes DescribeTargetGroups DescribeTargetGroupAttributes DescribeTargetHealth DescribeListeners DescribeListenerAttributes DescribeRules DescribeTags')
add('ReadNamedRegionalWaf','wafv2','GetWebACL ListTagsForResource',arn('wafv2','regional/webacl/scoutgrid-lab-api/*'))
add('ReadAlbWafAssociation','wafv2','GetWebACLForResource',arn('elasticloadbalancing','loadbalancer/app/scoutgrid-lab-api/*'))
add('ReadSydneyWafLists','wafv2','ListWebACLs')
add('ReadLogGroupMetadata','logs','DescribeLogGroups')
add('ReadLabLogGroupTags','logs','ListTagsForResource',arn('logs','log-group:/ecs/scoutgrid-lab/*'))
add('ReadLabSecretMetadataOnly','secretsmanager','DescribeSecret ListSecretVersionIds',[arn('secretsmanager','secret:scoutgrid-lab/'+n+'-??????') for n in ['runtime-db','application-settings','managed-installation']])
# A deny protects custody even if another attached policy is accidentally broad.
statements.extend([
 {'Sid':'DenySecretValueRetrieval','Effect':'Deny','Action':['secretsmanager:GetSecretValue','secretsmanager:BatchGetSecretValue'],'Resource':'*'},
 {'Sid':'ProtectRetainedBackend','Effect':'Deny','Action':['ecr:DeleteRepository','ecr:BatchDeleteImage','ecr:PutImageTagMutability'],'Resource':arn('ecr','repository/scoutgrid-lab-backend')},
 {'Sid':'ProtectStateAndHistory','Effect':'Deny','Action':['s3:DeleteBucket','s3:DeleteObject','s3:DeleteObjectVersion'],'Resource':[bucket,state]},
 {'Sid':'PreserveRetiredKeySchedules','Effect':'Deny','Action':['kms:CancelKeyDeletion','kms:EnableKey'],'Resource':[arn('kms','key/22cf6682-3133-47bd-af3e-200a1464b054'),arn('kms','key/ddb15ff2-ac4a-4eaa-92d4-7b697706ea11')]},
])
for item in statements:
 for action in item['Action']:
  service,name=action.split(':',1)
  reference=json.loads((root/f'service-reference/{service}.json').read_text())
  assert any(fnmatch.fnmatch(x['Name'],name) for x in reference['Actions']),action
policy={'Version':'2012-10-17','Statement':statements}
(root/'sydney-integrated-plan-policy.json').write_text(json.dumps(policy,indent=2)+'\n')
print(json.dumps({'statements':len(statements),'actions':sum(len(s['Action']) for s in statements),'compact_bytes':len(json.dumps(policy,separators=(',',':'))),'status':'unattached draft; action names verified against retained AWS SAR; Access Analyzer and final provider-plan qualification pending'}))
if __name__=='__main__':pass