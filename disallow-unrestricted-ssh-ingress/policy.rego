package env0

# Main deny rule - catches all unrestricted SSH ingress violations
deny[msg] {
	resource := input.plan.resource_changes[_]
	rule := get_ssh_ingress_rule(resource)
	cidr := get_unrestricted_cidr(rule)
	not is_cidr_allowed(cidr)
	msg := sprintf("%s: Unrestricted SSH ingress from %s is forbidden", [resource.address, cidr])
}

# Extract SSH ingress rule from aws_security_group_rule resources
get_ssh_ingress_rule(resource) = rule {
	resource.type == "aws_security_group_rule"
	rule := resource.change.after
	rule.type == "ingress"
	is_ssh_port_range(rule.from_port, rule.to_port)
}

# Extract SSH ingress rule from aws_security_group inline rules
get_ssh_ingress_rule(resource) = rule {
	resource.type == "aws_security_group"
	rule := resource.change.after.ingress[_]
	is_ssh_port_range(rule.from_port, rule.to_port)
}

# Check if port range includes SSH port 22
is_ssh_port_range(from_port, to_port) {
	from_port <= 22
	to_port >= 22
}

# Get unrestricted CIDR from IPv4 blocks
get_unrestricted_cidr(rule) = cidr {
	cidr := rule.cidr_blocks[_]
	is_unrestricted_cidr(cidr)
}

# Get unrestricted CIDR from IPv6 blocks
get_unrestricted_cidr(rule) = cidr {
	cidr := rule.ipv6_cidr_blocks[_]
	is_unrestricted_cidr(cidr)
}

# Check if CIDR is unrestricted (open to the world)
is_unrestricted_cidr(cidr) {
	cidr == "0.0.0.0/0"
}

is_unrestricted_cidr(cidr) {
	cidr == "::/0"
}

# Check if unrestricted CIDR is explicitly allowed via configuration
is_cidr_allowed(cidr) {
	allowed := input.policyData.allowed_ssh_cidrs[_]
	allowed == cidr
}