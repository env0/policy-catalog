package env0

# Deny GCP project IAM members with primitive roles
deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "google_project_iam_member"
    r.change.actions[_] == "create"
    r.change.after.role == "roles/owner"
    msg := "GCP primitive role 'owner' is not allowed at project level."
}

deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "google_project_iam_member"
    r.change.actions[_] == "update"
    r.change.after.role == "roles/owner"
    msg := "GCP primitive role 'owner' is not allowed at project level."
}

deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "google_project_iam_member"
    r.change.actions[_] == "create"
    r.change.after.role == "roles/editor"
    msg := "GCP primitive role 'editor' is not allowed at project level."
}

deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "google_project_iam_member"
    r.change.actions[_] == "update"
    r.change.after.role == "roles/editor"
    msg := "GCP primitive role 'editor' is not allowed at project level."
}

deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "google_project_iam_member"
    r.change.actions[_] == "create"
    r.change.after.role == "roles/viewer"
    msg := "GCP primitive role 'viewer' is not allowed at project level."
}

deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "google_project_iam_member"
    r.change.actions[_] == "update"
    r.change.after.role == "roles/viewer"
    msg := "GCP primitive role 'viewer' is not allowed at project level."
}