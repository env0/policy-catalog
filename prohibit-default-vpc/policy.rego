package env0.policy

deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "aws_instance"
    not r.change.after.vpc_security_group_ids
    msg := "Do not use the default VPC; explicitly define one."
}