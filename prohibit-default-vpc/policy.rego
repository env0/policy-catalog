package env0.policy

deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "aws_instance"
    r.change.after.vpc_security_group_ids == null
    msg := "Do not use the default VPC; explicitly define one."
}