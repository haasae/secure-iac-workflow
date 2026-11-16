# Unit tests for network.rego. Run with: conftest verify --policy policy
# Uses change() from s3_test.rego and single_change_plan() from iam_test.rego.
package main

import rego.v1

test_ingress_from_private_range_is_allowed if {
	after := {"cidr_ipv4": "10.0.0.0/16", "cidr_ipv6": null, "from_port": 443, "to_port": 443}
	msgs := deny with input as single_change_plan("aws_vpc_security_group_ingress_rule", after)
	count(msgs) == 0
}

test_ingress_from_any_ipv4_is_denied if {
	after := {"cidr_ipv4": "0.0.0.0/0", "cidr_ipv6": null, "from_port": 22, "to_port": 22}
	msgs := deny with input as single_change_plan("aws_vpc_security_group_ingress_rule", after)
	count(msgs) == 1
	some msg in msgs
	contains(msg, "open to the internet (0.0.0.0/0)")
}

test_ingress_from_any_ipv6_is_denied if {
	after := {"cidr_ipv4": null, "cidr_ipv6": "::/0", "from_port": 22, "to_port": 22}
	msgs := deny with input as single_change_plan("aws_vpc_security_group_ingress_rule", after)
	count(msgs) == 1
}

test_egress_to_anywhere_is_allowed if {
	after := {"cidr_ipv4": "0.0.0.0/0", "from_port": 443, "to_port": 443}
	msgs := deny with input as single_change_plan("aws_vpc_security_group_egress_rule", after)
	count(msgs) == 0
}

test_legacy_ingress_rule_open_is_denied if {
	after := {"type": "ingress", "cidr_blocks": ["10.0.0.0/16", "0.0.0.0/0"], "ipv6_cidr_blocks": null}
	msgs := deny with input as single_change_plan("aws_security_group_rule", after)
	count(msgs) == 1
}

test_legacy_egress_rule_open_is_allowed if {
	after := {"type": "egress", "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": null}
	msgs := deny with input as single_change_plan("aws_security_group_rule", after)
	count(msgs) == 0
}

test_inline_ingress_open_is_denied if {
	after := {"name": "x", "ingress": [{"cidr_blocks": [], "ipv6_cidr_blocks": ["::/0"], "from_port": 80, "to_port": 80}]}
	msgs := deny with input as single_change_plan("aws_security_group", after)
	count(msgs) == 1
	some msg in msgs
	contains(msg, "inline ingress rule")
}

test_security_group_without_inline_rules_is_allowed if {
	msgs := deny with input as single_change_plan("aws_security_group", {"name": "x"})
	count(msgs) == 0
}
