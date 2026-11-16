# Unit tests for iam.rego. Run with: conftest verify --policy policy
# Uses the change() builder defined in s3_test.rego (same package).
package main

import rego.v1

# A plan with no buckets and a single changed resource.
single_change_plan(kind, after) := {
	"format_version": "1.2",
	"configuration": {"root_module": {"resources": []}},
	"resource_changes": [change(kind, "test", after)],
}

policy_doc(statements) := json.marshal({"Version": "2012-10-17", "Statement": statements})

role_policy_plan(statements) := single_change_plan("aws_iam_role_policy", {"policy": policy_doc(statements)})

role_plan(statements) := single_change_plan("aws_iam_role", {"assume_role_policy": policy_doc(statements)})

scoped_statement := {
	"Effect": "Allow",
	"Action": ["s3:GetObject", "s3:PutObject"],
	"Resource": "arn:aws:s3:::example/*",
}

# --- Permission policies -----------------------------------------------------

test_scoped_policy_is_allowed if {
	msgs := deny with input as role_policy_plan([scoped_statement])
	count(msgs) == 0
}

test_single_statement_object_is_checked if {
	statement := object.union(scoped_statement, {"Action": "s3:*"})
	msgs := deny with input as role_policy_plan(statement)
	count(msgs) == 1
}

test_service_wildcard_action_is_denied if {
	statement := object.union(scoped_statement, {"Action": ["s3:GetObject", "s3:*"]})
	msgs := deny with input as role_policy_plan([statement])
	count(msgs) == 1
	some msg in msgs
	contains(msg, "wildcard action \"s3:*\"")
}

test_full_wildcard_action_as_string_is_denied if {
	statement := object.union(scoped_statement, {"Action": "*"})
	msgs := deny with input as role_policy_plan([statement])
	count(msgs) == 1
	some msg in msgs
	contains(msg, "wildcard action \"*\"")
}

test_wildcard_resource_is_denied if {
	statement := object.union(scoped_statement, {"Resource": "*"})
	msgs := deny with input as role_policy_plan([statement])
	count(msgs) == 1
	some msg in msgs
	contains(msg, "Resource \"*\"")
}

test_not_action_is_denied if {
	statement := {"Effect": "Allow", "NotAction": "iam:*", "Resource": "arn:aws:s3:::example/*"}
	msgs := deny with input as role_policy_plan([statement])
	count(msgs) == 1
	some msg in msgs
	contains(msg, "NotAction")
}

test_wildcard_in_deny_statement_is_allowed if {
	statement := {"Effect": "Deny", "Action": "*", "Resource": "*"}
	msgs := deny with input as role_policy_plan([scoped_statement, statement])
	count(msgs) == 0
}

test_unknown_policy_document_is_denied if {
	msgs := deny with input as single_change_plan("aws_iam_role_policy", {"name": "x"})
	count(msgs) == 1
	some msg in msgs
	contains(msg, "cannot be checked")
}

test_invalid_json_policy_is_denied if {
	msgs := deny with input as single_change_plan("aws_iam_role_policy", {"policy": "{not json"})
	count(msgs) == 1
	some msg in msgs
	contains(msg, "cannot be checked")
}

test_managed_policy_is_checked_too if {
	statement := object.union(scoped_statement, {"Action": "s3:*"})
	msgs := deny with input as single_change_plan("aws_iam_policy", {"policy": policy_doc([statement])})
	count(msgs) == 1
}

# --- Role trust policies -----------------------------------------------------

test_service_principal_trust_is_allowed if {
	statement := {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": "ec2.amazonaws.com"}}
	msgs := deny with input as role_plan([statement])
	count(msgs) == 0
}

test_star_principal_trust_is_denied if {
	statement := {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": "*"}
	msgs := deny with input as role_plan([statement])
	count(msgs) == 1
	some msg in msgs
	contains(msg, "any principal")
}

test_aws_star_principal_trust_is_denied if {
	statement := {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": ["arn:aws:iam::111122223333:root", "*"]}}
	msgs := deny with input as role_plan([statement])
	count(msgs) == 1
}

test_unknown_trust_policy_is_denied if {
	msgs := deny with input as single_change_plan("aws_iam_role", {"name": "x"})
	count(msgs) == 1
	some msg in msgs
	contains(msg, "trust policy is unknown")
}
