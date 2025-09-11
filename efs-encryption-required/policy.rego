package env0.policy

deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "aws_efs_file_system"
    "create" in r.change.actions
    r.change.after.encrypted != true
    msg := "EFS file systems must be encrypted."
}

deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "aws_efs_file_system"
    "update" in r.change.actions
    r.change.after.encrypted != true
    msg := "EFS file systems must be encrypted."
}