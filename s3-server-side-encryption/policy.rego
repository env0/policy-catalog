package env0

# Deny S3 buckets without server-side encryption configuration
deny[msg] {
    rc := input.plan.resource_changes[_]
    rc.type == "aws_s3_bucket"
    
    # Only check buckets that will exist after the change (not being deleted)
    not is_delete_action(rc.change.actions)
    
    # Check if there's no corresponding server-side encryption configuration
    not has_encryption_config(rc.address)
    
    msg := sprintf("%s: S3 bucket must have server-side encryption enabled", [rc.address])
}

# Deny deletion of server-side encryption configurations
deny[msg] {
    rc := input.plan.resource_changes[_]
    rc.type == "aws_s3_bucket_server_side_encryption_configuration"
    is_delete_action(rc.change.actions)
    
    msg := sprintf("%s: Server-side encryption configuration cannot be removed from S3 bucket", [rc.address])
}

# Deny server-side encryption configurations with null or missing algorithm
deny[msg] {
    rc := input.plan.resource_changes[_]
    rc.type == "aws_s3_bucket_server_side_encryption_configuration"
    
    # Only check configs that will exist after the change (not being deleted)
    not is_delete_action(rc.change.actions)
    rc.change.after
    
    # Check if any rule has null or missing sse_algorithm
    rule := rc.change.after.rule[_]
    encryption_config := rule.apply_server_side_encryption_by_default[_]
    not encryption_config.sse_algorithm
    
    msg := sprintf("%s: S3 bucket encryption configuration must specify a valid SSE algorithm", [rc.address])
}

# Helper function to check if a bucket has encryption configuration
has_encryption_config(bucket_address) {
    rc := input.plan.resource_changes[_]
    rc.type == "aws_s3_bucket_server_side_encryption_configuration"
    
    # Only consider configs that will exist after the change (not being deleted)
    not is_delete_action(rc.change.actions)
    rc.change.after
    
    # Extract bucket name from addresses to match them
    bucket_name := extract_bucket_name(bucket_address)
    config_bucket_name := extract_bucket_name(rc.address)
    bucket_name == config_bucket_name
    
    # Ensure the encryption config has valid rules
    rule := rc.change.after.rule[_]
    encryption_config := rule.apply_server_side_encryption_by_default[_]
    encryption_config.sse_algorithm
}

# Helper function to check if actions include delete
is_delete_action(actions) {
    actions[_] == "delete"
}

# Helper function to extract bucket name from resource address
extract_bucket_name(address) = name {
    # Handle both bucket and encryption config addresses
    parts := split(address, ".")
    name := parts[count(parts) - 1]
}