package env0.policy

# Deny EBS volumes that are not encrypted
deny[msg] {
    r := input.plan.resource_changes[_];
    r.type == "aws_ebs_volume";
    "create" in r.change.actions or "update" in r.change.actions;
    r.change.after.encrypted != true;
    msg := "EBS volumes must be encrypted.";
}