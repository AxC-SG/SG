# AWS account export

Read-only inventory performed on 2026-08-13. The active application resources were in `us-east-1`.

## Deployable CloudFormation exports

- `ai-discovery.json` is the exact processed template exported from the `ai-discovery` stack. It recreates the primary Bedrock/Lambda/DynamoDB/S3 setup, including four Bedrock agents, three action-group functions, two roles, and a guardrail.
- `ai-discovery-free-tier.json` is the exact processed template exported from `ai-discovery-free-tier-fixtures`. It recreates the low-cost fixture setup: two Bedrock agents, two Lambda functions, a DynamoDB table, an encrypted S3 bucket, and a guardrail. Its risky scenarios are disabled by default.
- `ec2-noscan-test.json` recreates the stopped `t3.micro` `NoScan test` instance. It must be launched in `us-east-1`; use an existing target-account key pair and restrict the public SSH/HTTP CIDRs.

Deploy a selected file from the target account, for example:

```sh
aws cloudformation deploy \
  --region us-east-1 \
  --stack-name ai-discovery-free-tier \
  --template-file ai-discovery-free-tier.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides ScannerAccountId=TARGET_OR_SCANNER_ACCOUNT_ID
```

For `ai-discovery.json`, supply `ScannerAccountId`; you may also override `ScannerExternalId`, `ProModel`, `LiteModel`, and `DocsBucketName`. For the EC2 template, add `--parameter-overrides KeyName=YOUR_TARGET_KEYPAIR SshIngressCidr=YOUR.IP.ADDRESS/32 HttpIngressCidr=YOUR.IP.ADDRESS/32`.

## Inventory and deliberate exclusions

The source account also contains AWS-managed Quick Setup / Resource Explorer resources, service-linked roles, and the CloudFormation template bucket. Those are service bootstrap resources and are recreated by AWS as needed, so they are not copied.

Data and credentials are intentionally **not** in these templates:

- S3 objects in the two application buckets. Copy the objects separately only if they are needed.
- DynamoDB table records. Export/import them separately if needed.
- Lambda code is preserved for the functions that used CloudFormation inline `ZipFile`; do not copy Lambda deployment packages or credentials outside the stack export.
- EC2 private key material and the source AMI root snapshot cannot be exported by a template. The EC2 template uses the discovered AMI ID; make an AMI or snapshot copy if you require the exact disk contents, and update `ImageId`.
- Bedrock foundation-model access is account/region permission state, not a CloudFormation resource. Enable access to the configured Nova models in the target account before deploying agents.
- Some original stack notes specify that Knowledge Bases and an AgentCore Gateway were not created by its CloudFormation template; set those up separately only if they are actually required.

Before closing the source account, validate the target deployment with a CloudFormation change set, copy any required data, test the agents/functions, and then cancel all source billing resources.
