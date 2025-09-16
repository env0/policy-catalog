package env0

# Helper function to check if actions include delete
is_delete_action(actions) {
	actions[_] == "delete"
}

# Deny EBS volumes that are not encrypted
deny[msg] {
	# Skip policy validation for destroy operations
	input.deploymentRequest.type != "destroy"

	r := input.plan.resource_changes[_]
	r.type == "aws_ebs_volume"
	not is_delete_action(r.change.actions)
	r.change.after
	r.change.after.encrypted != true
	msg := "EBS volumes must be encrypted."
}
