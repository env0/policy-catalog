package env0.policy

deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "aws_efs_file_system"
    r.change.after.encrypted != true
    msg := "EFS file systems must be encrypted."
}