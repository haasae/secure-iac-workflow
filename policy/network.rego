# Network baseline policy, evaluated against `terraform show -json` output.
#
# No security group may accept ingress from the whole internet (0.0.0.0/0 or
# ::/0). All three ways of declaring an ingress rule are covered:
#   - aws_vpc_security_group_ingress_rule
#   - aws_security_group_rule with type "ingress"
#   - inline ingress blocks on aws_security_group
#
# Known limits:
#   - a CIDR that is unknown at plan time is not flagged
#   - ranges that are very wide but not the full internet (for example
#     0.0.0.0/1) are not flagged
#   - egress is not restricted
package main

import rego.v1

open_cidrs := {"0.0.0.0/0", "::/0"}

deny contains msg if {
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type == "aws_vpc_security_group_ingress_rule"
	some field in ["cidr_ipv4", "cidr_ipv6"]
	cidr := rc.change.after[field]
	cidr in open_cidrs
	msg := sprintf("%s: ingress is open to the internet (%s)", [rc.address, cidr])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type == "aws_security_group_rule"
	rc.change.after.type == "ingress"
	some field in ["cidr_blocks", "ipv6_cidr_blocks"]
	some cidr in rc.change.after[field]
	cidr in open_cidrs
	msg := sprintf("%s: ingress is open to the internet (%s)", [rc.address, cidr])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type == "aws_security_group"
	some rule in rc.change.after.ingress
	some field in ["cidr_blocks", "ipv6_cidr_blocks"]
	some cidr in rule[field]
	cidr in open_cidrs
	msg := sprintf("%s: inline ingress rule is open to the internet (%s)", [rc.address, cidr])
}
