# Unit tests for s3.rego. Run with: conftest verify --policy policy
package main

import rego.v1

# --- Builders for a minimal plan JSON ----------------------------------------

bucket_cfg(name) := {
	"address": sprintf("aws_s3_bucket.%s", [name]),
	"type": "aws_s3_bucket",
	"name": name,
	"expressions": {"bucket": {"constant_value": name}},
}

companion_cfg(kind, name, bucket) := {
	"address": sprintf("%s.%s", [kind, name]),
	"type": kind,
	"name": name,
	"expressions": {"bucket": {"references": [
		sprintf("aws_s3_bucket.%s.id", [bucket]),
		sprintf("aws_s3_bucket.%s", [bucket]),
	]}},
}

change(kind, name, after) := {
	"address": sprintf("%s.%s", [kind, name]),
	"mode": "managed",
	"type": kind,
	"name": name,
	"change": {"actions": ["create"], "after": after},
}

good_pab := {
	"block_public_acls": true,
	"ignore_public_acls": true,
	"block_public_policy": true,
	"restrict_public_buckets": true,
}

good_versioning := {"versioning_configuration": [{"status": "Enabled"}]}

good_sse := {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]}

# One bucket named "this" with all three companion resources.
plan(pab, versioning, sse) := {
	"format_version": "1.2",
	"configuration": {"root_module": {"resources": [
		bucket_cfg("this"),
		companion_cfg(pab_type, "this", "this"),
		companion_cfg(versioning_type, "this", "this"),
		companion_cfg(sse_type, "this", "this"),
	]}},
	"resource_changes": [
		change("aws_s3_bucket", "this", {"bucket": "this"}),
		change(pab_type, "this", pab),
		change(versioning_type, "this", versioning),
		change(sse_type, "this", sse),
	],
}

good_plan := plan(good_pab, good_versioning, good_sse)

# --- Tests -------------------------------------------------------------------

test_compliant_plan_is_allowed if {
	msgs := deny with input as good_plan
	count(msgs) == 0
}

test_kms_encryption_is_allowed if {
	sse := {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]}
	msgs := deny with input as plan(good_pab, good_versioning, sse)
	count(msgs) == 0
}

test_public_access_flag_false_is_denied if {
	pab := object.union(good_pab, {"block_public_policy": false})
	msgs := deny with input as plan(pab, good_versioning, good_sse)
	count(msgs) == 1
	some msg in msgs
	contains(msg, "block_public_policy must be true")
}

test_public_access_flag_unknown_is_denied if {
	pab := object.remove(good_pab, ["restrict_public_buckets"])
	msgs := deny with input as plan(pab, good_versioning, good_sse)
	count(msgs) == 1
	some msg in msgs
	contains(msg, "restrict_public_buckets must be true")
}

test_versioning_suspended_is_denied if {
	versioning := {"versioning_configuration": [{"status": "Suspended"}]}
	msgs := deny with input as plan(good_pab, versioning, good_sse)
	count(msgs) == 1
	some msg in msgs
	contains(msg, "versioning status must be")
}

test_unapproved_encryption_algorithm_is_denied if {
	sse := {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "DES"}]}]}
	msgs := deny with input as plan(good_pab, good_versioning, sse)
	count(msgs) == 1
	some msg in msgs
	contains(msg, "default encryption must use")
}

test_encryption_without_rule_is_denied if {
	msgs := deny with input as plan(good_pab, good_versioning, {"rule": []})
	count(msgs) == 1
}

test_bucket_without_companions_is_denied if {
	bare := {
		"format_version": "1.2",
		"configuration": {"root_module": {"resources": [bucket_cfg("this")]}},
		"resource_changes": [change("aws_s3_bucket", "this", {"bucket": "this"})],
	}
	msgs := deny with input as bare
	count(msgs) == 3
}

test_non_plan_input_is_denied if {
	msgs := deny with input as {}
	count(msgs) == 1
	some msg in msgs
	contains(msg, "not Terraform plan JSON")
}

# The check this policy replaces passed as soon as one protected bucket existed
# anywhere in the plan. A second, unprotected bucket must still be denied.
test_second_unprotected_bucket_is_denied if {
	extra_cfg := array.concat(good_plan.configuration.root_module.resources, [bucket_cfg("logs")])
	extra_changes := array.concat(good_plan.resource_changes, [change("aws_s3_bucket", "logs", {"bucket": "logs"})])
	two_buckets := {
		"format_version": "1.2",
		"configuration": {"root_module": {"resources": extra_cfg}},
		"resource_changes": extra_changes,
	}
	msgs := deny with input as two_buckets
	count(msgs) == 3
	every msg in msgs {
		startswith(msg, "aws_s3_bucket.logs:")
	}
}

# A companion that points at another bucket must not count for this one.
test_companion_for_other_bucket_does_not_count if {
	swapped := {
		"format_version": "1.2",
		"configuration": {"root_module": {"resources": [
			bucket_cfg("this"),
			companion_cfg(pab_type, "other", "other"),
			companion_cfg(versioning_type, "this", "this"),
			companion_cfg(sse_type, "this", "this"),
		]}},
		"resource_changes": [
			change("aws_s3_bucket", "this", {"bucket": "this"}),
			change(pab_type, "other", good_pab),
			change(versioning_type, "this", good_versioning),
			change(sse_type, "this", good_sse),
		],
	}
	msgs := deny with input as swapped
	count(msgs) == 1
	some msg in msgs
	contains(msg, "no aws_s3_bucket_public_access_block references this bucket")
}
