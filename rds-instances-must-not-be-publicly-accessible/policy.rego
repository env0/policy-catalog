package env0.policy

# Helper function to check if actions include delete
is_delete_action(actions) {
    actions[_] == "delete"
}

# Deny RDS instances that are publicly accessible
deny[msg] {
    # Skip policy validation for destroy operations
    input.deploymentRequest.type != "destroy"
    
    r := input.plan.resource_changes[_];
    r.type == "aws_db_instance";
    not is_delete_action(r.change.actions);
    r.change.after;
    r.change.after.publicly_accessible == true;
    msg := "RDS instances must not be publicly accessible.";
}