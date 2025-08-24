package env0

# Check for public ACLs on aws_s3_bucket_acl resource
deny[msg] {
  rc := input.plan.resource_changes[_]
  rc.type == "aws_s3_bucket_acl"
  a := rc.change.after
  a.acl == "public-read"
  msg := sprintf("%s: public S3 bucket ACL (%s)", [rc.address, a.acl])
}

deny[msg] {
  rc := input.plan.resource_changes[_]
  rc.type == "aws_s3_bucket_acl"
  a := rc.change.after
  a.acl == "public-read-write"
  msg := sprintf("%s: public S3 bucket ACL (%s)", [rc.address, a.acl])
}

deny[msg] {
  rc := input.plan.resource_changes[_]
  rc.type == "aws_s3_bucket_policy"
  a := rc.change.after
  json.unmarshal(a.policy, pol)
  st := pol.Statement[_]
  lower(st.Effect) == "allow"
  is_public(st.Principal)
  msg := sprintf("%s: bucket policy allows public access", [rc.address])
}

is_public(p) { p == "*" } else { is_object(p); p.AWS == "*" } else { is_array(p); p[_] == "*" }
