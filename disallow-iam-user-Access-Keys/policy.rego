package env0

deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "aws_iam_access_key"
    msg := "IAM user access keys are forbidden. Use IAM roles."
}

allow[msg] {
	count(input.approvers) >= 1
	msg := sprintf("Deployment approved by %d approver(s)", [count(input.approvers)])
}