package network.no_open_sg

# Deny security groups / rules that open ingress to the world (0.0.0.0/0 or ::/0),
# except for the narrow, explicitly-allowed public ports (80/443 for public load
# balancers). Evaluated against `terraform show -json` plan output.

import rego.v1

world_cidrs := {"0.0.0.0/0", "::/0"}

# ports that are allowed to stay open to the world (public HTTP(S) entrypoints)
allowed_public_ports := {80, 443}

sg_rule_resources := {"aws_security_group_rule", "aws_vpc_security_group_ingress_rule"}

# --- aws_security_group with inline ingress blocks ---
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_security_group"
	after := rc.change.after
	some ingress in object.get(after, "ingress", [])
	some cidr in object.get(ingress, "cidr_blocks", [])
	cidr in world_cidrs
	not port_range_allowed(ingress.from_port, ingress.to_port)
	msg := sprintf("security group %q allows ingress from %s on port(s) %d-%d; restrict source CIDR or narrow to an allowed public port", [rc.address, cidr, ingress.from_port, ingress.to_port])
}

# --- standalone aws_security_group_rule / aws_vpc_security_group_ingress_rule ---
deny contains msg if {
	some rc in input.resource_changes
	rc.type in sg_rule_resources
	after := rc.change.after
	object.get(after, "type", "ingress") == "ingress"
	cidr := rule_cidr(after)
	cidr in world_cidrs
	from_port := object.get(after, "from_port", object.get(after, "from_port_range", 0))
	to_port := object.get(after, "to_port", object.get(after, "to_port_range", 0))
	not port_range_allowed(from_port, to_port)
	msg := sprintf("%s %q allows ingress from %s on port(s) %d-%d; restrict source CIDR or narrow to an allowed public port", [rc.type, rc.address, cidr, from_port, to_port])
}

rule_cidr(after) := after.cidr_blocks[_]

rule_cidr(after) := after.cidr_ipv4 if {
	after.cidr_ipv4
}

port_range_allowed(from_port, to_port) if {
	from_port == to_port
	from_port in allowed_public_ports
}
