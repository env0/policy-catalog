package env0.policy

# Helper function to check if actions include delete
is_delete_action(actions) {
	actions[_] == "delete"
}

# Deny GCP project IAM members with primitive roles
deny[msg] {
	r := input.plan.resource_changes[_]
	r.type == "google_project_iam_member"
	not is_delete_action(r.change.actions)
	r.change.after.role == "roles/owner"
	msg := "GCP primitive role 'owner' is not allowed at project level."
}

deny[msg] {
	r := input.plan.resource_changes[_]
	r.type == "google_project_iam_member"
	not is_delete_action(r.change.actions)
	r.change.after.role == "roles/editor"
	msg := "GCP primitive role 'editor' is not allowed at project level."
}

deny[msg] {
	r := input.plan.resource_changes[_]
	r.type == "google_project_iam_member"
	not is_delete_action(r.change.actions)
	r.change.after.role == "roles/viewer"
	msg := "GCP primitive role 'viewer' is not allowed at project level."
}