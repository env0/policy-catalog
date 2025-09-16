package env0

import rego.v1

# Helper function to check if actions include delete
is_delete_action(actions) if {
	actions[_] == "delete"
}

# Deny EFS file systems that are not encrypted
deny[msg] if {
	# Skip policy validation for destroy operations
	input.deploymentRequest.type != "destroy"

	r := input.plan.resource_changes[_]
	r.type == "aws_efs_file_system"
	not is_delete_action(r.change.actions)
	r.change.after
	r.change.after.encrypted != true
	msg := "EFS file systems must be encrypted."
}
