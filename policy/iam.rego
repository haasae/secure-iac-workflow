# IAM baseline policy, evaluated against `terraform show -json` output.
#
# Permission policies (inline and managed):
#   - no Allow statement may use a wildcard action ("*" or "service:*")
#   - no Allow statement may use NotAction
#   - no Allow statement may use Resource "*"
# Role trust policies:
#   - no Allow statement may use a wildcard principal
#
# A policy document that is unknown at plan time, or is not valid JSON, is
# denied. Otherwise an uncheckable document would pass without being read.
#
# Known limits:
#   - Resource "*" is denied even for the few actions that only accept "*";
#     those need a deliberate exception when they come up
#   - conditions are not evaluated, so a wildcard narrowed by a Condition is
#     still denied
#   - the aws_iam_policy_document data source is not inspected directly, only
#     the resources that end up using its JSON
package main

import rego.v1

iam_policy_types := {
	"aws_iam_policy",
	"aws_iam_role_policy",
	"aws_iam_user_policy",
	"aws_iam_group_policy",
}

# IAM allows a single value where a list is expected. Normalise to a list.
as_array(x) := x if is_array(x)

as_array(x) := [x] if not is_array(x)

policy_changes contains rc if {
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type in iam_policy_types
	rc.change.after != null
}

role_changes contains rc if {
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type == "aws_iam_role"
	rc.change.after != null
}

# A document can only be checked if it is a known, valid JSON string.
checkable(doc) if {
	is_string(doc)
	json.is_valid(doc)
}

allow_statements(doc) := [s |
	checkable(doc)
	some s in as_array(json.unmarshal(doc).Statement)
	s.Effect == "Allow"
]

wildcard_action(action) if action == "*"

wildcard_action(action) if endswith(action, ":*")

wildcard_principal(principal) if principal == "*"

wildcard_principal(principal) if {
	is_object(principal)
	some value in principal
	some entry in as_array(value)
	entry == "*"
}

# --- Permission policies -----------------------------------------------------

deny contains msg if {
	some rc in policy_changes
	not checkable(object.get(rc.change.after, "policy", null))
	msg := sprintf("%s: policy document is unknown at plan time or not valid JSON, so it cannot be checked", [rc.address])
}

deny contains msg if {
	some rc in policy_changes
	some s in allow_statements(rc.change.after.policy)
	some action in as_array(s.Action)
	wildcard_action(action)
	msg := sprintf("%s: Allow statement uses wildcard action \"%s\"", [rc.address, action])
}

deny contains msg if {
	some rc in policy_changes
	some s in allow_statements(rc.change.after.policy)
	s.NotAction
	msg := sprintf("%s: Allow statement uses NotAction, which grants everything except the listed actions", [rc.address])
}

deny contains msg if {
	some rc in policy_changes
	some s in allow_statements(rc.change.after.policy)
	some resource in as_array(s.Resource)
	resource == "*"
	msg := sprintf("%s: Allow statement uses Resource \"*\"", [rc.address])
}

# --- Role trust policies -----------------------------------------------------

deny contains msg if {
	some rc in role_changes
	not checkable(object.get(rc.change.after, "assume_role_policy", null))
	msg := sprintf("%s: trust policy is unknown at plan time or not valid JSON, so it cannot be checked", [rc.address])
}

deny contains msg if {
	some rc in role_changes
	some s in allow_statements(rc.change.after.assume_role_policy)
	wildcard_principal(s.Principal)
	msg := sprintf("%s: trust policy allows any principal to assume the role", [rc.address])
}
