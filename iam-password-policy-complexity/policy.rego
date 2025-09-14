package env0.policy

deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "aws_iam_account_password_policy"
    "create" in r.change.actions
    r.change.after.minimum_password_length < input.policyData.min_length
    msg := "IAM password policy does not meet minimum length requirement."
}

deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "aws_iam_account_password_policy"
    "update" in r.change.actions
    r.change.after.minimum_password_length < input.policyData.min_length
    msg := "IAM password policy does not meet minimum length requirement."
}