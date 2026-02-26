# secure-iac-workflow

Terraform repo for provisioning an AWS S3 bucket with:

- Versioning enabled
- S3 public access blocked
- Default server-side encryption enabled
- CI checks for formatting, validation, plan, and a simple policy check

## Folder structure

- `infra/` Terraform files
- `policy/` policy check script used by CI
- `.github/workflows/` GitHub Actions workflow

## Prerequisites

- Terraform `>= 1.5`
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

## Apply

(This is optional) If you want to create the bucket in AWS:

```bash
terraform -chdir=infra apply -var='bucket_name=your-unique-bucket-name'
```

## Notes on security

- The S3 bucket includes `aws_s3_bucket_public_access_block` with all four protections enabled.
- S3 versioning is enabled to help with recovery from accidental changes/deletions.
- S3 default server-side encryption is enabled (AES256).
- The policy script is intentionally simple (grep-based) and is meant as a teaching example, not a full policy engine.
- The JSON plan policy script validates the planned resources (public access block, versioning, and encryption) before apply.
- Do not commit real secrets or credential files. `.gitignore` excludes common Terraform state and variable files.

## CI behavior

On every pull request, GitHub Actions runs:

- `terraform fmt -check`
- `terraform validate`
- `terraform plan`
- `policy/check_public_access_block.sh`
- `terraform show -json` (to generate `tfplan.json`)
- `policy/check_tfplan_json.sh`
