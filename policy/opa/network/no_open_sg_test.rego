package network.no_open_sg

import rego.v1

test_deny_open_ssh_inline_sg if {
	deny["security group \"aws_security_group.bad\" allows ingress from 0.0.0.0/0 on port(s) 22-22; restrict source CIDR or narrow to an allowed public port"] with input as {"resource_changes": [{
		"type": "aws_security_group",
		"address": "aws_security_group.bad",
		"change": {"after": {"ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]}},
	}]}
}

test_allow_https_to_world if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "aws_security_group",
		"address": "aws_security_group.lb",
		"change": {"after": {"ingress": [{"from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}]}},
	}]}
}

test_allow_restricted_cidr if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "aws_security_group",
		"address": "aws_security_group.internal",
		"change": {"after": {"ingress": [{"from_port": 5432, "to_port": 5432, "cidr_blocks": ["10.0.0.0/16"]}]}},
	}]}
}

test_deny_wide_port_range_open_to_world if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "aws_security_group",
		"address": "aws_security_group.bad",
		"change": {"after": {"ingress": [{"from_port": 0, "to_port": 65535, "cidr_blocks": ["0.0.0.0/0"]}]}},
	}]}
}

test_deny_standalone_sg_rule if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "aws_security_group_rule",
		"address": "aws_security_group_rule.bad",
		"change": {"after": {"type": "ingress", "from_port": 3389, "to_port": 3389, "cidr_blocks": ["0.0.0.0/0"]}},
	}]}
}

test_deny_ipv6_open_to_world if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "aws_security_group",
		"address": "aws_security_group.bad_v6",
		"change": {"after": {"ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["::/0"]}]}},
	}]}
}

test_allow_egress_rule_type_ignored if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "aws_security_group_rule",
		"address": "aws_security_group_rule.egress_all",
		"change": {"after": {"type": "egress", "from_port": 0, "to_port": 65535, "cidr_blocks": ["0.0.0.0/0"]}},
	}]}
}
