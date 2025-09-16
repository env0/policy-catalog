package env0.policy

# Helper function to check if actions include create
is_create_action(actions) {
    actions[_] == "create"
}

# Helper function to check if actions include update
is_update_action(actions) {
    actions[_] == "update"
}

# Deny RDS instances that are publicly accessible
deny[msg] {
    r := input.plan.resource_changes[_];
    r.type == "aws_db_instance";
    is_create_action(r.change.actions);
    r.change.after.publicly_accessible == true;
    msg := "RDS instances must not be publicly accessible.";
}

deny[msg] {
    r := input.plan.resource_changes[_];
    r.type == "aws_db_instance";
    is_update_action(r.change.actions);
    r.change.after.publicly_accessible == true;
    msg := "RDS instances must not be publicly accessible.";
}