package env0

# Deny S3 buckets without server-side encryption configuration
deny[msg] {
    rc := input.plan.resource_changes[_]
    rc.type == "aws_s3_bucket"
    rc.change.actions[_] == "create"
    
    # Check if there's no corresponding server-side encryption configuration
    not has_encryption_config(rc.address)
    
    msg := sprintf("%s: S3 bucket must have server-side encryption enabled", [rc.address])
}

# Deny server-side encryption configurations with null or missing algorithm
deny[msg] {
    rc := input.plan.resource_changes[_]
    rc.type == "aws_s3_bucket_server_side_encryption_configuration"
    rc.change.actions[_] == "create"
    
    # Check if any rule has null or missing sse_algorithm
    rule := rc.change.after.rule[_]
    not rule.apply_server_side_encryption_by_default.sse_algorithm
    
    msg := sprintf("%s: S3 bucket encryption configuration must specify a valid SSE algorithm", [rc.address])
}

# Helper function to check if a bucket has encryption configuration
has_encryption_config(bucket_address) {
    rc := input.plan.resource_changes[_]
    rc.type == "aws_s3_bucket_server_side_encryption_configuration"
    
    # Extract bucket name from addresses to match them
    bucket_name := extract_bucket_name(bucket_address)
    config_bucket_name := extract_bucket_name(rc.address)
    bucket_name == config_bucket_name
    
    # Ensure the encryption config has valid rules
    rule := rc.change.after.rule[_]
    rule.apply_server_side_encryption_by_default.sse_algorithm
}

# Helper function to extract bucket name from resource address
extract_bucket_name(address) = name {
    # Handle both bucket and encryption config addresses
    parts := split(address, ".")
    name := parts[count(parts) - 1]
}