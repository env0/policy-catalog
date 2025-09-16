package env0.policy

# Deny RDS instances that are publicly accessible
deny[msg] {
    r := input.plan.resource_changes[_];
    r.type == "aws_db_instance";
    "create" in r.change.actions;
    r.change.after.publicly_accessible == true;
    msg := "RDS instances must not be publicly accessible.";
}

deny[msg] {
    r := input.plan.resource_changes[_];
    r.type == "aws_db_instance";
    "update" in r.change.actions;
    r.change.after.publicly_accessible == true;
    msg := "RDS instances must not be publicly accessible.";
}