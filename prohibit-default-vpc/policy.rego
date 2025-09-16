package env0.policy

# Helper function to check if actions include create
is_create_action(actions) {
    actions[_] == "create"
}

# Helper function to check if actions include update
is_update_action(actions) {
    actions[_] == "update"
}

# Deny EC2 instances that are not explicitly placed in a custom VPC
deny[msg] {
    r := input.plan.resource_changes[_];
    r.type == "aws_instance";
    is_create_action(r.change.actions);
    not r.change.after.subnet_id;
    msg := "Do not use the default VPC; explicitly define a subnet_id to use a custom VPC.";
}

deny[msg] {
    r := input.plan.resource_changes[_];
    r.type == "aws_instance";
    is_update_action(r.change.actions);
    not r.change.after.subnet_id;
    msg := "Do not use the default VPC; explicitly define a subnet_id to use a custom VPC.";
}