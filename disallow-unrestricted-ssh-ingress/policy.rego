package env0

# Deny AWS security group rules with unrestricted SSH ingress (0.0.0.0/0)
deny[msg] {
	r := input.plan.resource_changes[_]
	r.type == "aws_security_group_rule"
	r.change.after.type == "ingress"
	r.change.after.from_port <= 22
	r.change.after.to_port >= 22
	cidr := r.change.after.cidr_blocks[_]
	cidr == "0.0.0.0/0"
	not is_ssh_allowed_from_unrestricted_cidr()
	msg := sprintf("%s: Unrestricted SSH ingress from 0.0.0.0/0 is forbidden", [r.address])
}

# Deny AWS security group rules with unrestricted SSH ingress (IPv6 equivalent)
deny[msg] {
	r := input.plan.resource_changes[_]
	r.type == "aws_security_group_rule"
	r.change.after.type == "ingress"
	r.change.after.from_port <= 22
	r.change.after.to_port >= 22
	cidr := r.change.after.ipv6_cidr_blocks[_]
	cidr == "::/0"
	not is_ssh_allowed_from_unrestricted_cidr()
	msg := sprintf("%s: Unrestricted SSH ingress from ::/0 is forbidden", [r.address])
}

# Deny AWS security groups with inline rules allowing unrestricted SSH ingress
deny[msg] {
	r := input.plan.resource_changes[_]
	r.type == "aws_security_group"
	rule := r.change.after.ingress[_]
	rule.from_port <= 22
	rule.to_port >= 22
	cidr := rule.cidr_blocks[_]
	cidr == "0.0.0.0/0"
	not is_ssh_allowed_from_unrestricted_cidr()
	msg := sprintf("%s: Unrestricted SSH ingress from 0.0.0.0/0 is forbidden", [r.address])
}

# Deny AWS security groups with inline rules allowing unrestricted SSH ingress (IPv6)
deny[msg] {
	r := input.plan.resource_changes[_]
	r.type == "aws_security_group"
	rule := r.change.after.ingress[_]
	rule.from_port <= 22
	rule.to_port >= 22
	cidr := rule.ipv6_cidr_blocks[_]
	cidr == "::/0"
	not is_ssh_allowed_from_unrestricted_cidr()
	msg := sprintf("%s: Unrestricted SSH ingress from ::/0 is forbidden", [r.address])
}

# Helper function to check if SSH from unrestricted CIDR is explicitly allowed
is_ssh_allowed_from_unrestricted_cidr() {
	allowed_cidrs := input.policyData.allowed_ssh_cidrs[_]
	allowed_cidrs == "0.0.0.0/0"
}

is_ssh_allowed_from_unrestricted_cidr() {
	allowed_cidrs := input.policyData.allowed_ssh_cidrs[_]
	allowed_cidrs == "::/0"
}