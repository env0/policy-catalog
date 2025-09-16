package env0.policy

# Deny EC2 instances that are not explicitly placed in a custom VPC
deny[msg] {
    r := input.plan.resource_changes[_];
    r.type == "aws_instance";
    r.change.actions[_] == "create";
    not r.change.after.subnet_id;
    msg := "Do not use the default VPC; explicitly define a subnet_id to use a custom VPC.";
}

deny[msg] {
    r := input.plan.resource_changes[_];
    r.type == "aws_instance";
    r.change.actions[_] == "update";
    not r.change.after.subnet_id;
    msg := "Do not use the default VPC; explicitly define a subnet_id to use a custom VPC.";
}