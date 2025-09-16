package env0.policy

# Helper function to check if actions include create
is_create_action(actions) {
    actions[_] == "create"
}

# Helper function to check if actions include update
is_update_action(actions) {
    actions[_] == "update"
}

# Deny EFS file systems that are not encrypted
deny[msg] {
    r := input.plan.resource_changes[_];
    r.type == "aws_efs_file_system";
    is_create_action(r.change.actions);
    r.change.after.encrypted != true;
    msg := "EFS file systems must be encrypted.";
}

deny[msg] {
    r := input.plan.resource_changes[_];
    r.type == "aws_efs_file_system";
    is_update_action(r.change.actions);
    r.change.after.encrypted != true;
    msg := "EFS file systems must be encrypted.";
}