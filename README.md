# secure-iac-workflow

This is a secure Terraform starter workflow for AWS S3. 

## Purpose

To provision a bucket and enforce security controls, both in code and in CI before applying to cloud resources. Uses a local validation workflow to test infra changes without immediately applying.

## What happens

1. Creates an S3 bucket with versioning enabled
2. Enforces S3 public access block settings
3. Enforces default server-side encryption (AES256)
4. A policy gate in CI checks that Terrafrorm plan JSON has the required secure resources/settings

## Folder structure

- `infra/` Terraform files
- `policy/` policy check script used by CI
- `.github/workflows/` GitHub Actions workflow

## Prerequisites

- Terraform `>= 1.5`
- A Git Bash terminal
- AWS credentials (if you want to run a real plan/apply against your account)

## Local run (quick start)

From the repo root:

```bash
terraform -chdir=infra fmt -recursive
terraform -chdir=infra init
terraform -chdir=infra validate
terraform -chdir=infra plan -refresh=false -out=tfplan -var='bucket_name=your-unique-bucket-name'
terraform -chdir=infra show -json tfplan > infra/tfplan.json
bash policy/check_public_access_block.sh
bash policy/check_tfplan_json.sh
```

NOTE: Your bucket name must be unique! Therefore I recommend adding "$(Get-Random)" at the end of the name. For example:  
```
"bucket_name={your name}-secure-iac-$(Get-Random)"
```
## Apply

Finally, if you want to create the bucket in AWS:

```bash
terraform -chdir=infra apply -var='bucket_name=your-unique-bucket-name'
```

## What to do with the bucket
Use it as a secure object storage bucket. With the current setup, the most common things you can do are:

1. Upload and store files
    - Backups
    - Documents
    - App assets (that are private)
    - Logs/exports

2. Recover older versions of files
    - Versioning is enabled, so overwriting a file keeps older versions.
    - Useful for accidental overwrites/deletions.
3. Use it as a private data bucket for apps
    - EC2/Lambda/ECS apps can read/write with IAM permissions.
    - Public access is blocked, which is good for internal/private use.
4. What I like to use it for: Practicing AWS security and IaC workflows
    - I do this by changing Terraform and testing new changes in policy checks. 

## Possible future improvements
1. Replacing AES256 with KMS encryption
2. Adding lifecycle rules
3. Replacing grep-based source policy checks with a real policy engine
4. Adding bucket tags


## Notes on security

- The S3 bucket includes `aws_s3_bucket_public_access_block` with all four protections enabled.
- S3 versioning is enabled to help with recovery from accidental changes/deletions.
- S3 default server-side encryption is enabled (AES256).
- The policy script is grep-based and is not meant as a full policy engine.
- The JSON plan policy script validates the planned resources (public access block, versioning, and encryption) before applying.
- Do not commit real secrets or credential files! `.gitignore` excludes common Terraform state and variable files.

## CI behavior

On every pull request, GitHub Actions runs:

- `terraform fmt -check`
- `terraform validate`
- `terraform plan`
- `policy/check_public_access_block.sh`
- `terraform show -json` (to generate `tfplan.json`)
- `policy/check_tfplan_json.sh`
