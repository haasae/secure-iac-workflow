# S3 baseline policy, evaluated against `terraform show -json` output.
#
# Every aws_s3_bucket in the root module must have its own:
#   - public access block with all four protections set to true
#   - versioning with status "Enabled"
#   - default server-side encryption using AES256 or aws:kms
#
# Buckets are tied to their companion resources through the references in the
# Terraform configuration (bucket = aws_s3_bucket.<name>.id), not through
# planned values, because a new bucket's id is unknown at plan time.
#
# Known limits (fail closed where possible):
#   - only the root module is inspected, not child modules
#   - a companion resource that names its bucket with a literal string instead
#     of a reference is not counted, so the bucket is reported as uncovered
#   - a value that is unknown at plan time is treated as non-compliant
package main

import rego.v1

pab_type := "aws_s3_bucket_public_access_block"

versioning_type := "aws_s3_bucket_versioning"

sse_type := "aws_s3_bucket_server_side_encryption_configuration"

pab_flags := [
	"block_public_acls",
	"ignore_public_acls",
	"block_public_policy",
	"restrict_public_buckets",
]

allowed_sse := {"AES256", "aws:kms"}

config_resources := input.configuration.root_module.resources

# Addresses of every bucket declared in the root module.
buckets contains r.address if {
	some r in config_resources
	r.type == "aws_s3_bucket"
}

# Addresses of resources of the given type whose `bucket` argument references
# the given bucket.
companions(kind, bucket) := {r.address |
	some r in config_resources
	r.type == kind
	bucket in r.expressions.bucket.references
}

# Address of a planned root-module resource without its count/for_each index.
base_address(rc) := sprintf("%s.%s", [rc.type, rc.name]) if not rc.module_address

# Planned values for a configuration address (one entry per instance).
planned(addr) := [rc.change.after |
	some rc in input.resource_changes
	rc.mode == "managed"
	base_address(rc) == addr
	rc.change.after != null
]

# --- Input sanity ------------------------------------------------------------

# Without this, an empty or wrong file would produce no denials and pass.
deny contains msg if {
	not input.format_version
	msg := "input is not Terraform plan JSON (format_version is missing)"
}

# --- Public access block -----------------------------------------------------

deny contains msg if {
	some bucket in buckets
	count(companions(pab_type, bucket)) == 0
	msg := sprintf("%s: no %s references this bucket", [bucket, pab_type])
}

deny contains msg if {
	some bucket in buckets
	some addr in companions(pab_type, bucket)
	some after in planned(addr)
	some flag in pab_flags
	object.get(after, flag, false) != true
	msg := sprintf("%s: %s must be true (bucket %s)", [addr, flag, bucket])
}

# --- Versioning --------------------------------------------------------------

deny contains msg if {
	some bucket in buckets
	count(companions(versioning_type, bucket)) == 0
	msg := sprintf("%s: no %s references this bucket", [bucket, versioning_type])
}

deny contains msg if {
	some bucket in buckets
	some addr in companions(versioning_type, bucket)
	some after in planned(addr)
	not versioning_enabled(after)
	msg := sprintf("%s: versioning status must be \"Enabled\" (bucket %s)", [addr, bucket])
}

versioning_enabled(after) if after.versioning_configuration[0].status == "Enabled"

# --- Default encryption ------------------------------------------------------

deny contains msg if {
	some bucket in buckets
	count(companions(sse_type, bucket)) == 0
	msg := sprintf("%s: no %s references this bucket", [bucket, sse_type])
}

deny contains msg if {
	some bucket in buckets
	some addr in companions(sse_type, bucket)
	some after in planned(addr)
	not encrypted(after)
	msg := sprintf("%s: default encryption must use AES256 or aws:kms (bucket %s)", [addr, bucket])
}

encrypted(after) if {
	count(after.rule) > 0
	every rule in after.rule {
		some default_cfg in rule.apply_server_side_encryption_by_default
		default_cfg.sse_algorithm in allowed_sse
	}
}
