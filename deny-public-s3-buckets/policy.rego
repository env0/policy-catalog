package env0

# Check for public ACLs on aws_s3_bucket_acl resource
deny[msg] if {
	rc := input.plan.resource_changes[_]
	rc.type == "aws_s3_bucket_acl"
	a := rc.change.after
	a.acl == "public-read"
	msg := sprintf("%s: public S3 bucket ACL (%s)", [rc.address, a.acl])
}

deny[msg] if {
	rc := input.plan.resource_changes[_]
	rc.type == "aws_s3_bucket_acl"
	a := rc.change.after
	a.acl == "public-read-write"
	msg := sprintf("%s: public S3 bucket ACL (%s)", [rc.address, a.acl])
}

deny[msg] if {
	rc := input.plan.resource_changes[_]
	rc.type == "aws_s3_bucket_policy"
	a := rc.change.after
	json.unmarshal(a.policy, pol)
	st := pol.Statement[_]
	lower(st.Effect) == "allow"
	wildcard_principal_check(st.Principal)
	msg := sprintf("%s: bucket policy allows public access", [rc.address])
}

# Check for public access block settings
deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "aws_s3_bucket_public_access_block"
	r.change.after.block_public_acls != true
	msg := sprintf("%s: S3 bucket must enable 'block_public_acls'", [r.address])
}

deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "aws_s3_bucket_public_access_block"
	r.change.after.block_public_policy != true
	msg := sprintf("%s: S3 bucket must enable 'block_public_policy'", [r.address])
}

deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "aws_s3_bucket_public_access_block"
	r.change.after.ignore_public_acls != true
	msg := sprintf("%s: S3 bucket must enable 'ignore_public_acls'", [r.address])
}

deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "aws_s3_bucket_public_access_block"
	r.change.after.restrict_public_buckets != true
	msg := sprintf("%s: S3 bucket must enable 'restrict_public_buckets'", [r.address])
}

wildcard_principal_check(prin) if prin == "*"

wildcard_principal_check(prin) if {
	is_object(prin)
	prin.AWS == "*"
}

wildcard_principal_check(prin) if {
	is_array(prin)
	prin[_] == "*"
}
