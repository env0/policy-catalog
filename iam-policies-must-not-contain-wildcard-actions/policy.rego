package env0

import rego.v1

deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "aws_iam_policy"
	doc := json.unmarshal(r.change.after.policy)
	contains(doc.Statement[_].Action[_], "*")
	msg := "IAM policies must not use wildcard '*' actions."
}
