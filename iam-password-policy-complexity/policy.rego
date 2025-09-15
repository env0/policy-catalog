package env0.policy

# Check minimum password length
deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "aws_iam_account_password_policy"
    "create" in r.change.actions or "update" in r.change.actions
    r.change.after.minimum_password_length < input.policyConfiguration.min_length
    msg := "IAM password policy does not meet minimum length requirement."
}

# Check for required uppercase characters
deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "aws_iam_account_password_policy"
    "create" in r.change.actions or "update" in r.change.actions
    not r.change.after.require_uppercase_characters
    msg := "IAM password policy must require uppercase characters."
}

# Check for required lowercase characters
deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "aws_iam_account_password_policy"
    "create" in r.change.actions or "update" in r.change.actions
    not r.change.after.require_lowercase_characters
    msg := "IAM password policy must require lowercase characters."
}

# Check for required numbers
deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "aws_iam_account_password_policy"
    "create" in r.change.actions or "update" in r.change.actions
    not r.change.after.require_numbers
    msg := "IAM password policy must require numbers."
}

# Check for required symbols
deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "aws_iam_account_password_policy"
    "create" in r.change.actions or "update" in r.change.actions
    not r.change.after.require_symbols
    msg := "IAM password policy must require symbols."
}

# Check for password change allowance (conditional based on policy configuration)
deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "aws_iam_account_password_policy"
    "create" in r.change.actions or "update" in r.change.actions
    input.policyConfiguration.require_user_password_changes == true
    not r.change.after.allow_users_to_change_password
    msg := "IAM password policy must allow users to change passwords."
}

# Check maximum password age
deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "aws_iam_account_password_policy"
    "create" in r.change.actions or "update" in r.change.actions
    r.change.after.max_password_age < input.policyConfiguration.max_password_age
    msg := "IAM password policy does not meet maximum password age requirement."
}

# Check password reuse prevention
deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "aws_iam_account_password_policy"
    "create" in r.change.actions or "update" in r.change.actions
    r.change.after.password_reuse_prevention < input.policyConfiguration.min_password_reuse_prevention
    msg := "IAM password policy does not meet password reuse prevention requirement."
}