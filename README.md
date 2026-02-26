# secure-iac-workflow


This is a secure Terraform starter workflow for AWS S3. 

## Purpose

To provision a bucket and enforce security controls, both in code and in CI before applying to cloud resources. Uses a local validation workflow to test infra changes without immediately applying.

## What happens

1. Creates an S3 bucket with versioning enabled
2. Enforces S3 public access block settings
3. Enforces default server-side encryption (AES256)
4. A policy gate in CI checks that Terrafrorm plan JSON has the required secure resources/settings

- Versioning enabled
- S3 public access blocked
- Default server-side encryption enabled
- Uses a CI policy gate to verify the Terraform plan JSON contains required secure resources/settings

## Folder structure

- `infra/` Terraform files
- `policy/` policy check script used by CI
- `.github/workflows/` GitHub Actions workflow

## Prerequisites

- Terraform `>= 1.5`
- AWS credentials (only if you want to run a real plan/apply against your account)

## Local run (quick start)

From repo root:

```bash
terraform -chdir=infra fmt -recursive
terraform -chdir=infra init
terraform -chdir=infra validate
terraform -chdir=infra plan -refresh=false -out=tfplan -var='bucket_name=your-unique-bucket-name'
terraform -chdir=infra show -json tfplan > infra/tfplan.json
bash policy/check_public_access_block.sh
bash policy/check_tfplan_json.sh
```

## Apply

If you want to create the bucket in AWS:

```bash
terraform -chdir=infra apply -var='bucket_name=your-unique-bucket-name'
```

## Notes on security

- The S3 bucket includes `aws_s3_bucket_public_access_block` with all four protections enabled
- S3 versioning is enabled to help with recovery from accidental changes or deletions
- S3 default server-side encryption is enabled (AES256)
- The policy script is only grep-based and can NOT be used as a full policy engine
- The JSON plan policy script validates the planned resources (public access block, versioning, and encryption) before applying
- DO NOT COMMIT REAL SECRETS OR CREDENTIAL FILES! `.gitignore` excludes common Terraform state and variable files.

## CI behavior

On every pull request, GitHub Actions runs:

- `terraform fmt -check`
- `terraform validate`
- `terraform plan`
- `policy/check_public_access_block.sh`
- `terraform show -json` (to generate `tfplan.json`)
- `policy/check_tfplan_json.sh`
