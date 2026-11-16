# secure-iac-workflow

This is a secure Terraform workflow for AWS: an S3 bucket, an IAM role that can use it, and a small network, with policy checks that run on every pull request.

## Purpose

To provision a bucket and enforce security controls, both in code and in CI before applying to cloud resources. Uses a local validation workflow to test infra changes without immediately applying.

## What happens

1. Creates an S3 bucket with versioning enabled
2. Enforces S3 public access block settings
3. Enforces default server-side encryption (AES256)
4. Creates an IAM role for an EC2 application, limited to listing this bucket and reading/writing its objects
5. Creates a VPC and a security group that only accepts HTTPS from inside the VPC
6. A policy gate in CI checks the Terraform plan JSON against the policies in `policy/`

## Folder structure

- `infra/` Terraform files
- `policy/` Rego policies and their unit tests, run with Conftest
- `.github/workflows/` GitHub Actions workflow

## Prerequisites

- Terraform `>= 1.5`
- A Git Bash terminal
- [Conftest](https://www.conftest.dev/install/) `>= 0.70` (for the policy checks)
- AWS credentials (if you want to run a real plan/apply against your account)

## Local run (quick start)

From the repo root:

```bash
terraform -chdir=infra fmt -recursive
terraform -chdir=infra init
terraform -chdir=infra validate
terraform -chdir=infra plan -refresh=false -out=tfplan -var='bucket_name=your-unique-bucket-name'
terraform -chdir=infra show -json tfplan > infra/tfplan.json
conftest verify --policy policy
conftest test infra/tfplan.json --policy policy
```

NOTE: Your bucket name must be unique! Therefore I recommend adding "$(Get-Random)" at the end of the name. For example:  
```
"bucket_name={your name}-secure-iac-$(Get-Random)"
```
## Apply

Finally, if you want to create the resources in AWS (bucket, IAM role, VPC and security group):

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
3. Adding bucket tags
4. Extending the policies to child modules


## Notes on security

- The S3 bucket includes `aws_s3_bucket_public_access_block` with all four protections enabled.
- S3 versioning is enabled to help with recovery from accidental changes/deletions.
- S3 default server-side encryption is enabled (AES256).
- The policies in `policy/s3.rego` are evaluated against the plan JSON, so they check what Terraform is about to do, not what the source files look like.
- Every bucket must have its own public access block, versioning and encryption. One protected bucket does not cover another.
- The S3 policies only inspect the root module. Unknown values and non-plan input fail the check.
- `policy/iam.rego` rejects wildcard actions, `NotAction`, `Resource "*"` and wildcard principals in trust policies. A policy document that is unknown at plan time is rejected, because it cannot be read.
- `policy/network.rego` rejects security group ingress from `0.0.0.0/0` and `::/0`.
- Each policy file lists its known limits at the top.
- Do not commit real secrets or credential files! `.gitignore` excludes common Terraform state and variable files.

## CI behavior

On every pull request, GitHub Actions runs:

- Conftest install (pinned version, build provenance verified)
- `conftest verify` (unit tests for the policies)
- `terraform fmt -check`
- `terraform validate`
- `terraform plan`
- `terraform show -json` (to generate `tfplan.json`)
- `conftest test` (policies against `tfplan.json`)
