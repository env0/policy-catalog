package env0

deny[msg] {
    patterns := ["*.metal", "g5.*"]
    pattern := patterns[_]
    r := input.plan.resource_changes[_]
    r.type == "aws_instance"
    glob.match(pattern, [], r.change.after.instance_type)
    msg := "Creation of expensive instance types is restricted."
}
