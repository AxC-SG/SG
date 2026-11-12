"""Render review-only scopes for Terraform HCL resources; never attach policies."""
from pathlib import Path
import json,hashlib,fnmatch
root=Path(__file__).resolve().parent
account,region='736486260824','ap-southeast-2'
def arn(service,tail):return f'arn:aws:{service}:{region}:{account}:{tail}'
region_values={'aws:RequestedRegion':region}
tags={'Application':'ScoutGrid','Environment':'lab','Profile':'Standard','ManagedBy':'Terraform'}
def tagged(kind):return {f'aws:{kind}Tag/{k}':v for k,v in tags.items()}
def statement(sid,service,actions,resources='*',equals=None,extra=None,regional=True):
 s={'Sid':sid,'Effect':'Allow','Action':[service+':'+a for a in actions.split()],'Resource':resources}
 c={'StringEquals':dict(region_values)} if regional else {}
 if equals:c.setdefault('StringEquals',{}).update(equals)
 if extra:
  for op,values in extra.items():c.setdefault(op,{}).update(values)
 if c:s['Condition']=c
 return s
base=json.loads((root/'sydney-integrated-plan-policy.json').read_text())['Statement']
# Common role documents remain separate from mutable infrastructure scopes.
common=base+[statement('WriteOnlyExactCurrentState','s3','PutObject',f'arn:aws:s3:::scoutgrid-lab-tfstate-{account}-{region}/standard/lab/terraform.tfstate',regional=False)]
def ec2(types):return [arn('ec2',t+'/*') for t in types.split()]
buckets=[f'arn:aws:s3:::scoutgrid-lab-{account}-{k}' for k in ['imports','exports']]
bootstrap=[
 statement('CreateTaggedFreshSymmetricKeys','kms','CreateKey',equals={**tagged('Request'),'aws:RequestTag/ManagedBy':['Terraform','ScoutGridReleaseOperator'],'kms:KeySpec':'SYMMETRIC_DEFAULT','kms:KeyUsage':'ENCRYPT_DECRYPT','kms:KeyOrigin':'AWS_KMS'},extra={'BoolIfExists':{'kms:MultiRegion':'false','kms:BypassPolicyLockoutSafetyCheck':'false'}}),
 statement('EnableRotationOnFreshLabKeys','kms','EnableKeyRotation',arn('kms','key/*'),{**tagged('Resource'),'aws:ResourceTag/ManagedBy':['Terraform','ScoutGridReleaseOperator']}),
 statement('TagFreshLabKeys','kms','TagResource',arn('kms','key/*'),{**tagged('Request'),**tagged('Resource'),'aws:RequestTag/ManagedBy':['Terraform','ScoutGridReleaseOperator'],'aws:ResourceTag/ManagedBy':['Terraform','ScoutGridReleaseOperator']}),
 statement('CreateOnlyNamedSydneyLabBuckets','s3','CreateBucket',buckets,{'s3:LocationConstraint':region},regional=False),
 statement('ConfigureOnlyLabArtifactBuckets','s3','PutBucketPublicAccessBlock PutBucketOwnershipControls PutBucketVersioning PutEncryptionConfiguration PutBucketPolicy PutBucketCORS PutBucketTagging',buckets,regional=False),
 statement('CreateTaggedLabIdentityPool','cognito-idp','CreateUserPool',equals=tagged('Request')),
 statement('CreateTaggedLabFrontend','amplify','CreateApp',equals=tagged('Request')),
 statement('CreateOnlyEcsServiceLinkedRole','iam','CreateServiceLinkedRole',f'arn:aws:iam::{account}:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS',{'iam:AWSServiceName':'ecs.amazonaws.com'},regional=False),
]
foundation=[
 statement('CreateTaggedNetworkRoots','ec2','AllocateAddress CreateInternetGateway CreateVpc',ec2('elastic-ip internet-gateway vpc'),tagged('Request')),
 statement('CreateTaggedVpcChildren','ec2','CreateRouteTable CreateSecurityGroup CreateSubnet',ec2('route-table security-group subnet'),tagged('Request')),
 statement('CreateTaggedSingleNat','ec2','CreateNatGateway',ec2('natgateway'),tagged('Request')),
 statement('CreateTaggedS3Endpoint','ec2','CreateVpcEndpoint',ec2('vpc-endpoint'),{**tagged('Request'),'ec2:VpceServiceName':f'com.amazonaws.{region}.s3'}),
 statement('TagOnlyNewNetworkResources','ec2','CreateTags',ec2('elastic-ip internet-gateway vpc route-table security-group subnet natgateway vpc-endpoint'),{**tagged('Request'),'ec2:CreateAction':['AllocateAddress','CreateInternetGateway','CreateVpc','CreateRouteTable','CreateSecurityGroup','CreateSubnet','CreateNatGateway','CreateVpcEndpoint']}),
 statement('UseOnlyTaggedLabVpc','ec2','CreateSubnet CreateRouteTable CreateSecurityGroup CreateNatGateway CreateVpcEndpoint AttachInternetGateway ModifyVpcAttribute',ec2('vpc'),tagged('Resource')),
 statement('UseOnlyTaggedNatInputs','ec2','CreateNatGateway',ec2('subnet elastic-ip'),tagged('Resource')),
 statement('UseOnlyTaggedEndpointRoutes','ec2','CreateVpcEndpoint',ec2('route-table'),tagged('Resource')),
 statement('AttachOnlyTaggedGateway','ec2','AttachInternetGateway',ec2('internet-gateway'),tagged('Resource')),
 statement('ConfigureOnlyTaggedRoutes','ec2','AssociateRouteTable CreateRoute',ec2('route-table'),tagged('Resource')),
 statement('ConfigureOnlyTaggedSubnets','ec2','AssociateRouteTable ModifySubnetAttribute',ec2('subnet'),tagged('Resource')),
 statement('RemoveDefaultDbEgress','ec2','RevokeSecurityGroupEgress',ec2('security-group'),tagged('Resource')),
 statement('CreateNamedDatabaseGroups','rds','CreateDBParameterGroup CreateDBSubnetGroup',[arn('rds','pg:scoutgrid-lab-postgres16'),arn('rds','subgrp:scoutgrid-lab')],tagged('Request')),
 statement('ConfigureNamedDatabaseParameters','rds','ModifyDBParameterGroup',arn('rds','pg:scoutgrid-lab-postgres16')),
 statement('CreateOnlyPrivateEncryptedManagedPasswordDb','rds','CreateDBInstance',[arn('rds','db:scoutgrid-lab'),arn('rds','pg:scoutgrid-lab-postgres16'),arn('rds','subgrp:scoutgrid-lab')],tagged('Request'),{'Bool':{'rds:PubliclyAccessible':'false','rds:ManageMasterUserPassword':'true'}}),
 statement('TagNamedDatabaseResources','rds','AddTagsToResource',[arn('rds','db:scoutgrid-lab'),arn('rds','pg:scoutgrid-lab-postgres16'),arn('rds','subgrp:scoutgrid-lab')],tagged('Request')),
 statement('UseFreshDatabaseKeyThroughAwsServices','kms','Decrypt GenerateDataKey',arn('kms','key/RENDER_FRESH_DATABASE_KEY'),{'kms:CallerAccount':account,'kms:ViaService':[f'rds.{region}.amazonaws.com',f'secretsmanager.{region}.amazonaws.com']}),
 statement('GrantFreshDatabaseKeyToAwsResources','kms','CreateGrant',arn('kms','key/RENDER_FRESH_DATABASE_KEY'),{'kms:CallerAccount':account,'kms:ViaService':[f'rds.{region}.amazonaws.com',f'secretsmanager.{region}.amazonaws.com']},{'Bool':{'kms:GrantIsForAWSResource':'true'}}),
 statement('OnlyRdsForwardedManagedSecretSetup','secretsmanager','CreateSecret TagResource',arn('secretsmanager','secret:rds!db-*'),extra={'ForAnyValue:StringEquals':{'aws:CalledVia':'rds.amazonaws.com'}}),
 statement('ReadAwsManagedSecretsKey','kms','DescribeKey',arn('kms','key/*'),extra={'ForAnyValue:StringEquals':{'kms:ResourceAliases':'alias/aws/secretsmanager'}}),
 statement('ConfigureExactNewIdentityPool','cognito-idp','CreateResourceServer CreateUserPoolClient CreateUserPoolDomain CreateManagedLoginBranding',arn('cognito-idp','userpool/RENDER_FRESH_POOL_ID')),
 statement('CreateExactLabFrontendBranch','amplify','CreateBranch TagResource',arn('amplify','apps/RENDER_FRESH_APP_ID/branches/lab'),tagged('Request')),
 statement('CreateImmutableNamedRepository','ecr','CreateRepository TagResource',arn('ecr','repository/scoutgrid-lab-backend'),tagged('Request')),
]
roles=[f'arn:aws:iam::{account}:role/scoutgrid-lab-{r}' for r in ['api-execution','worker-execution','migrator-execution','api-task','worker-task']]
trusted_runtime=[
 statement('ManageOnlyFiveReviewedRuntimeRoles','iam','CreateRole GetRole UpdateAssumeRolePolicy PutRolePolicy GetRolePolicy ListRolePolicies ListAttachedRolePolicies TagRole UntagRole',roles,regional=False),
 statement('PassOnlyReviewedTaskRolesToEcs','iam','PassRole',roles,{'iam:PassedToService':'ecs-tasks.amazonaws.com'},regional=False),
 *[statement('RegisterReviewed'+r.title()+'TaskDefinition','ecs','RegisterTaskDefinition',arn('ecs',f'task-definition/scoutgrid-lab-{r}:*'),tagged('Request'),{'StringEqualsIfExists':{'ecs:privileged':'false'},'NumericEquals':{'ecs:task-cpu':cpu,'ecs:task-memory':memory},'ForAllValues:StringEquals':{'ecs:compute-compatibility':'FARGATE'},'Null':{'ecs:compute-compatibility':'false'}}) for r,cpu,memory in [('api',512,2048),('worker',1024,4096),('migrator',1024,4096)]],
 statement('TagNewReviewedTaskDefinitions','ecs','TagResource',[arn('ecs',f'task-definition/scoutgrid-lab-{r}:*') for r in ['api','worker','migrator']],tagged('Request')),
]
# This inventory-bound cleanup template intentionally cannot render without every
# captured resource identity and the separate data/key/backup disposition decision.
cleanup=[
 statement('StopOnlyCapturedLabServices','ecs','UpdateService DeleteService',[arn('ecs','service/scoutgrid-lab/api'),arn('ecs','service/scoutgrid-lab/worker')]),
 statement('StopOnlyCapturedLabTasks','ecs','StopTask',arn('ecs','task/scoutgrid-lab/RENDER_CAPTURED_TASK_ID')),
 statement('DeregisterOnlyCapturedTaskRevisions','ecs','DeregisterTaskDefinition',arn('ecs','task-definition/RENDER_CAPTURED_TASK_REVISION')),
 statement('DeleteOnlyLabCluster','ecs','DeleteCluster',arn('ecs','cluster/scoutgrid-lab')),
 statement('DeleteCapturedRuntimeRoles','iam','DeleteRolePolicy DeleteRole',roles,regional=False),
 statement('DeleteCapturedLogGroups','logs','DeleteLogGroup',[arn('logs',f'log-group:/ecs/scoutgrid-lab/{r}:*') for r in ['api','worker','migrator']]),
 statement('DisableAndDeleteCapturedDatabase','rds','ModifyDBInstance DeleteDBInstance',arn('rds','db:scoutgrid-lab')),
 statement('DeleteCapturedDbGroups','rds','DeleteDBParameterGroup DeleteDBSubnetGroup',[arn('rds','pg:scoutgrid-lab-postgres16'),arn('rds','subgrp:scoutgrid-lab')]),
 statement('DeleteOnlyCapturedDisposableBackup','rds','DeleteDBSnapshot',arn('rds','snapshot:RENDER_CAPTURED_APPROVED_SNAPSHOT')),
 statement('DeleteCapturedFrontend','amplify','DeleteDomainAssociation DeleteBranch DeleteApp',[arn('amplify','apps/RENDER_FRESH_APP_ID'),arn('amplify','apps/RENDER_FRESH_APP_ID/branches/lab'),arn('amplify','apps/RENDER_FRESH_APP_ID/domains/lab.scoutgrid.io')]),
 statement('DisableAndDeleteCapturedPool','cognito-idp','UpdateUserPool DeleteUserPool DeleteResourceServer DeleteUserPoolClient DeleteUserPoolDomain DeleteManagedLoginBranding',arn('cognito-idp','userpool/RENDER_FRESH_POOL_ID')),
 statement('EmptyOnlyCapturedLabObjectVersions','s3','DeleteObject DeleteObjectVersion AbortMultipartUpload',[b+'/RENDER_CAPTURED_APPROVED_OBJECT_KEY' for b in buckets],regional=False),
 statement('ListAndDeleteOnlyLabArtifactBuckets','s3','ListBucket ListBucketVersions ListBucketMultipartUploads DeleteBucket DeleteBucketPolicy PutBucketPublicAccessBlock PutBucketOwnershipControls PutBucketVersioning PutEncryptionConfiguration PutBucketCORS',buckets,regional=False),
 statement('DeleteCapturedRegionalWebAcl','wafv2','DisassociateWebACL DeleteWebACL',arn('wafv2','regional/webacl/scoutgrid-lab-api/RENDER_CAPTURED_WEBACL_ID')),
 statement('RemoveCapturedAlbWafAssociation','wafv2','DisassociateWebACL',arn('elasticloadbalancing','loadbalancer/app/scoutgrid-lab-api/RENDER_CAPTURED_ALB_ID')),
 statement('DeleteCapturedAlbTree','elasticloadbalancing','DeleteLoadBalancer DeleteTargetGroup DeleteListener DeleteRule',[arn('elasticloadbalancing',v) for v in ['loadbalancer/app/scoutgrid-lab-api/RENDER_CAPTURED_ALB_ID','targetgroup/scoutgrid-lab-api/RENDER_CAPTURED_TARGET_ID','listener/app/scoutgrid-lab-api/RENDER_CAPTURED_LISTENER_PATH','listener-rule/app/scoutgrid-lab-api/RENDER_CAPTURED_RULE_PATH']]),
]
for kind,actions in [('vpc','DeleteVpc DetachInternetGateway'),('subnet','DeleteSubnet DisassociateRouteTable'),('route-table','DeleteRouteTable DeleteRoute DisassociateRouteTable'),('internet-gateway','DetachInternetGateway DeleteInternetGateway'),('elastic-ip','ReleaseAddress'),('natgateway','DeleteNatGateway'),('vpc-endpoint','DeleteVpcEndpoints'),('security-group','DeleteSecurityGroup RevokeSecurityGroupIngress RevokeSecurityGroupEgress')]:
 cleanup.append(statement('DeleteCaptured'+kind.replace('-','').title(),'ec2',actions,arn('ec2',kind+'/RENDER_CAPTURED_'+kind.replace('-','_').upper()+'_ID')))
runtime_infra=[
 statement('CreateTaggedRuntimeGroups','ec2','CreateSecurityGroup',ec2('security-group'),tagged('Request')),
 statement('CreateGroupsOnlyInCapturedVpc','ec2','CreateSecurityGroup',arn('ec2','vpc/RENDER_FRESH_VPC_ID')),
 statement('TagOnlyNewRuntimeGroupsAndRules','ec2','CreateTags',ec2('security-group security-group-rule'),{**tagged('Request'),'ec2:CreateAction':['CreateSecurityGroup','AuthorizeSecurityGroupIngress','AuthorizeSecurityGroupEgress']}),
 statement('ConfigureOnlyCapturedRuntimeGroups','ec2','AuthorizeSecurityGroupIngress AuthorizeSecurityGroupEgress RevokeSecurityGroupIngress RevokeSecurityGroupEgress',[arn('ec2','security-group/RENDER_CAPTURED_'+r+'_GROUP') for r in ['DATABASE','ALB','API','WORKER','MIGRATOR']]),
 statement('CreateOnlyTaggedLabCluster','ecs','CreateCluster TagResource',arn('ecs','cluster/scoutgrid-lab'),tagged('Request')),
 statement('ConfigureOnlyLabCluster','ecs','UpdateClusterSettings',arn('ecs','cluster/scoutgrid-lab')),
 statement('CreateOnlyTaggedRuntimeLogs','logs','CreateLogGroup',[arn('logs',f'log-group:/ecs/scoutgrid-lab/{r}:*') for r in ['api','worker','migrator']],tagged('Request')),
 statement('ConfigureOnlyRuntimeLogRetention','logs','PutRetentionPolicy TagResource',[arn('logs',f'log-group:/ecs/scoutgrid-lab/{r}:*') for r in ['api','worker','migrator']]),
 statement('CreateOnlyTaggedPublicLabAlb','elasticloadbalancing','CreateLoadBalancer',arn('elasticloadbalancing','loadbalancer/app/scoutgrid-lab-api/*'),{**tagged('Request'),'elasticloadbalancing:Scheme':'internet-facing'}),
 statement('CreateOnlyTaggedLabTarget','elasticloadbalancing','CreateTargetGroup',arn('elasticloadbalancing','targetgroup/scoutgrid-lab-api/*'),tagged('Request')),
 statement('CreateOnlyHttpsLabListener','elasticloadbalancing','CreateListener',arn('elasticloadbalancing','loadbalancer/app/scoutgrid-lab-api/RENDER_CAPTURED_ALB_ID'),extra={'ForAllValues:StringEquals':{'elasticloadbalancing:ListenerProtocol':'HTTPS','elasticloadbalancing:SecurityPolicy':'ELBSecurityPolicy-TLS13-1-2-2021-06'},'Null':{'elasticloadbalancing:ListenerProtocol':'false','elasticloadbalancing:SecurityPolicy':'false'}}),
 statement('CreateOnlyLabHostRule','elasticloadbalancing','CreateRule',arn('elasticloadbalancing','listener/app/scoutgrid-lab-api/RENDER_CAPTURED_LISTENER_PATH')),
 statement('ConfigureOnlyCapturedAlbTree','elasticloadbalancing','ModifyLoadBalancerAttributes ModifyTargetGroupAttributes AddTags',[arn('elasticloadbalancing','loadbalancer/app/scoutgrid-lab-api/RENDER_CAPTURED_ALB_ID'),arn('elasticloadbalancing','targetgroup/scoutgrid-lab-api/RENDER_CAPTURED_TARGET_ID'),arn('elasticloadbalancing','listener/app/scoutgrid-lab-api/RENDER_CAPTURED_LISTENER_PATH'),arn('elasticloadbalancing','listener-rule/app/scoutgrid-lab-api/RENDER_CAPTURED_RULE_PATH')]),
 statement('CreateOnlyTaggedNamedRegionalWaf','wafv2','CreateWebACL TagResource',arn('wafv2','regional/webacl/scoutgrid-lab-api/*'),tagged('Request')),
 statement('AssociateOnlyCapturedRegionalWafAndAlb','wafv2','AssociateWebACL',[arn('wafv2','regional/webacl/scoutgrid-lab-api/RENDER_CAPTURED_WEBACL_ID'),arn('elasticloadbalancing','loadbalancer/app/scoutgrid-lab-api/RENDER_CAPTURED_ALB_ID')]),
]
secret_custody=[
 statement('CreateOnlyThreeEncryptedLabSecrets','secretsmanager','CreateSecret',[arn('secretsmanager','secret:scoutgrid-lab/'+n+'-??????') for n in ['runtime-db','application-settings','managed-installation']],{**tagged('Request'),'aws:RequestTag/ManagedBy':'ScoutGridReleaseOperator','secretsmanager:KmsKeyArn':arn('kms','key/RENDER_FRESH_APPLICATION_KEY')}),
 statement('TagOnlyThreeLabSecrets','secretsmanager','TagResource',[arn('secretsmanager','secret:scoutgrid-lab/'+n+'-??????') for n in ['runtime-db','application-settings','managed-installation']],{**tagged('Request'),'aws:RequestTag/ManagedBy':'ScoutGridReleaseOperator'}),
 statement('WriteAndInspectOnlyLabSecretVersions','secretsmanager','PutSecretValue UpdateSecretVersionStage DescribeSecret ListSecretVersionIds',[arn('secretsmanager','secret:scoutgrid-lab/'+n+'-??????') for n in ['runtime-db','application-settings','managed-installation']],{**tagged('Resource'),'aws:ResourceTag/ManagedBy':'ScoutGridReleaseOperator'}),
 statement('UseKeyOnlyForNewSecretsThroughSecretsManager','kms','GenerateDataKey Decrypt',arn('kms','key/RENDER_FRESH_APPLICATION_KEY'),{'kms:ViaService':f'secretsmanager.{region}.amazonaws.com','kms:CallerAccount':account},extra={'StringLike':{'kms:EncryptionContext:SecretARN':[arn('secretsmanager','secret:scoutgrid-lab/'+n+'-??????') for n in ['runtime-db','application-settings','managed-installation']]}}),
 {'Sid':'NeverRetrieveSecretValues','Effect':'Deny','Action':['secretsmanager:GetSecretValue','secretsmanager:BatchGetSecretValue'],'Resource':'*'},
]
identity_operator=[
 statement('EnrollOnlyApprovedAliasesInCapturedPool','cognito-idp','AdminCreateUser AdminGetUser DescribeUserPool',arn('cognito-idp','userpool/RENDER_FRESH_POOL_ID')),
]
frontend_operator=[
 statement('DeployOnlyCapturedLabBranch','amplify','CreateDeployment StartDeployment GetBranch ListJobs',arn('amplify','apps/RENDER_FRESH_APP_ID/branches/lab')),
 statement('ReadOnlyCapturedLabDeploymentJobs','amplify','GetJob',arn('amplify','apps/RENDER_FRESH_APP_ID/branches/lab/jobs/*')),
 statement('ReadOnlyCapturedLabApp','amplify','GetApp ListDomainAssociations',arn('amplify','apps/RENDER_FRESH_APP_ID')),
 statement('AssociateOnlyLabChildDomain','amplify','CreateDomainAssociation GetDomainAssociation',arn('amplify','apps/RENDER_FRESH_APP_ID/domains/lab.scoutgrid.io')),
]
retirement=[
 statement('RetireOnlyCapturedFreshSecretsWithRecovery','secretsmanager','DeleteSecret',[arn('secretsmanager','secret:RENDER_CAPTURED_RUNTIME_SECRET'),arn('secretsmanager','secret:RENDER_CAPTURED_APPLICATION_SECRET'),arn('secretsmanager','secret:RENDER_CAPTURED_ENROLLMENT_SECRET')],extra={'NumericEquals':{'secretsmanager:RecoveryWindowInDays':7},'BoolIfExists':{'secretsmanager:ForceDeleteWithoutRecovery':'false'}}),
 statement('ScheduleOnlyCapturedFreshKeysAfterConsumersRemoved','kms','ScheduleKeyDeletion',[arn('kms','key/RENDER_FRESH_DATABASE_KEY'),arn('kms','key/RENDER_FRESH_OBJECT_KEY')],extra={'NumericEquals':{'kms:ScheduleKeyDeletionPendingWindowInDays':30}}),
]
policies={'identity-operator.template':identity_operator,'frontend-operator.template':frontend_operator,'retirement.template':retirement,'secret-custody.template':secret_custody,'runtime-infra-apply.template':runtime_infra,'common-read-state':common,'trusted-foundation-bootstrap':bootstrap,'foundation-apply.template':foundation,'trusted-runtime-bootstrap':trusted_runtime,'inventory-cleanup.template':cleanup}
manifest={}
for name,statements in policies.items():
 for s in statements:
  for action in s['Action']:
   service,a=action.split(':',1);reference=json.loads((root/f'service-reference/{service}.json').read_text())
   assert any(fnmatch.fnmatch(x['Name'],a) for x in reference['Actions']),action
 data=(json.dumps({'Version':'2012-10-17','Statement':statements},indent=2)+'\n').encode()
 path=root/(name+'.json');path.write_bytes(data)
 manifest[name]={'file':str(path),'sha256':hashlib.sha256(data).hexdigest(),'statements':len(statements),'compact_bytes':len(json.dumps({'Version':'2012-10-17','Statement':statements},separators=(',',':'))),'render_required':'RENDER_' in data.decode(),'attached':False}
trust={'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'AWS':f'arn:aws:iam::{account}:role/managed/AccountFullAccessRole'},'Action':'sts:AssumeRole'}]}
(root/'operator-trust.json').write_text(json.dumps(trust,indent=2)+'\n')
(root/'execution-policy-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest,indent=2))
# Managed policies have a 6,144-character limit; keep every attachable shard
# below 5,500 bytes rather than overflowing the aggregate inline-role quota.
shard_manifest={}
for name,statements in policies.items():
 chunks=[];current=[]
 for item in statements:
  candidate=current+[item]
  size=len(json.dumps({'Version':'2012-10-17','Statement':candidate},separators=(',',':')))
  if size>5500 and current:chunks.append(current);current=[item]
  else:current=candidate
 if current:chunks.append(current)
 for index,chunk in enumerate(chunks,1):
  doc={'Version':'2012-10-17','Statement':chunk}; compact=json.dumps(doc,separators=(',',':'))
  assert len(compact)<=5500
  name_with_index=f'{name}.part{index}.json';path=root/name_with_index;path.write_text(compact+'\n')
  shard_manifest[name_with_index]={'sha256':hashlib.sha256((compact+'\n').encode()).hexdigest(),'compact_bytes':len(compact),'attached':False}
(root/'managed-policy-shards.json').write_text(json.dumps(shard_manifest,indent=2)+'\n')
print('Managed policy shard size checks passed.')
