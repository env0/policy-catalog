package env0

import rego.v1

deny[msg] if {
	pattern := input.policyData.disallowed_patterns[_]
	r := input.plan.resource_changes[_]
	r.type == "aws_instance"
	glob.match(pattern, [], r.change.after.instance_type)
	msg := "Creation of expensive instance types is restricted."
}
