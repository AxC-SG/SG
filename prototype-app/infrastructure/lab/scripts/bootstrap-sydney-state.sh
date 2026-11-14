#!/usr/bin/env bash
set -euo pipefail

account_id=736486260824
region=ap-southeast-2
bucket=scoutgrid-lab-tfstate-736486260824-ap-southeast-2
state_key=standard/lab/terraform.tfstate

case "${1:-verify}" in
  create|verify) action="${1:-verify}" ;;
  *) echo "Usage: $0 [create|verify]" >&2; exit 2 ;;
esac

export AWS_PAGER=""
actual_account=$(aws sts get-caller-identity --region "$region" --query Account --output text)
if [[ "$actual_account" != "$account_id" ]]; then
  printf 'Expected AWS account %s, got %s.\n' "$account_id" "$actual_account" >&2
  exit 1
fi

s3_bucket() {
  local operation=$1
  shift
  aws s3api "$operation" --region "$region" --bucket "$bucket" \
    --expected-bucket-owner "$account_id" "$@"
}

if [[ "$action" == create ]]; then
  existing=$(aws s3api list-buckets --region "$region" \
    --query "length(Buckets[?Name=='$bucket'])" --output text)
  if [[ "$existing" != 0 ]]; then
    echo "The bucket already exists. Run verify to inspect its settings." >&2
    exit 1
  fi

  aws s3api create-bucket --region "$region" --bucket "$bucket" \
    --create-bucket-configuration "LocationConstraint=$region" \
    --object-ownership BucketOwnerEnforced
  aws s3api wait bucket-exists --region "$region" --bucket "$bucket" \
    --expected-bucket-owner "$account_id"
  s3_bucket put-public-access-block --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  s3_bucket put-bucket-encryption --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"},"BucketKeyEnabled":true}]}'
  s3_bucket put-bucket-versioning --versioning-configuration Status=Enabled
  s3_bucket put-bucket-tagging --tagging \
    'TagSet=[{Key=Application,Value=ScoutGrid},{Key=Environment,Value=lab},{Key=Purpose,Value=TerraformState}]'
fi

location=$(s3_bucket get-bucket-location --query LocationConstraint --output text)
ownership=$(s3_bucket get-bucket-ownership-controls --query 'OwnershipControls.Rules[0].ObjectOwnership' --output text)
private=$(s3_bucket get-public-access-block --query 'PublicAccessBlockConfiguration.*' --output text)
versioning=$(s3_bucket get-bucket-versioning --query Status --output text)
encryption=$(s3_bucket get-bucket-encryption \
  --query 'ServerSideEncryptionConfiguration.Rules[0].[ApplyServerSideEncryptionByDefault.SSEAlgorithm,BucketKeyEnabled]' \
  --output text)

if [[ "$location" != "$region" || "$ownership" != BucketOwnerEnforced ||
      "$private" != $'True\tTrue\tTrue\tTrue' || "$versioning" != Enabled ||
      "$encryption" != $'aws:kms\tTrue' ]]; then
  printf 'State bucket verification failed. Region=%s, ownership=%s, public access blocks=%s, versioning=%s, encryption=%s\n' \
    "$location" "$ownership" "$private" "$versioning" "$encryption" >&2
  exit 1
fi

printf 'Verified private, versioned SSE-KMS state bucket %s in %s.\n' "$bucket" "$region"
printf 'State key %s\nLock key %s.tflock\n' "$state_key" "$state_key"
