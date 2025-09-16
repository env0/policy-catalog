package env0.policy

# Helper function to check if actions include delete
is_delete_action(actions) {
    actions[_] == "delete"
}

# Deny EC2 instances that are not explicitly placed in a custom VPC
deny[msg] {
    # Skip policy validation for destroy operations
    input.deploymentRequest.type != "destroy"
    
    r := input.plan.resource_changes[_];
    r.type == "aws_instance";
    not is_delete_action(r.change.actions);
    r.change.after;
    not r.change.after.subnet_id;
    msg := "Do not use the default VPC; explicitly define a subnet_id to use a custom VPC.";
}