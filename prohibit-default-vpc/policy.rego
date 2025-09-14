package env0.policy

# Deny EC2 instances that are not explicitly placed in a custom VPC
# This policy assumes that if no subnet_id is specified, the instance will use the default VPC
deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "aws_instance"
    ("create" in r.change.actions or "update" in r.change.actions)
    not r.change.after.subnet_id
    msg := "Do not use the default VPC; explicitly define a subnet_id to use a custom VPC."
}