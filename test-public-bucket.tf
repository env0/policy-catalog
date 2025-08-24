# Terraform code that will be DENIED by the deny-public-s3-buckets policy

# Example 1: S3 bucket with public-read ACL (will be denied)
resource "aws_s3_bucket" "public_read_bucket" {
  bucket = "my-public-read-bucket-${random_id.bucket_suffix.hex}"
  acl    = "public-read"
}

# Example 2: S3 bucket with public-read-write ACL (will be denied)
resource "aws_s3_bucket" "public_write_bucket" {
  bucket = "my-public-write-bucket-${random_id.bucket_suffix.hex}"
  acl    = "public-read-write"
}

# Example 3: S3 bucket with public bucket policy (will be denied)
resource "aws_s3_bucket" "bucket_with_public_policy" {
  bucket = "my-bucket-with-policy-${random_id.bucket_suffix.hex}"
}

resource "aws_s3_bucket_policy" "public_policy" {
  bucket = aws_s3_bucket.bucket_with_public_policy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"
        Action = "s3:GetObject"
        Resource = "${aws_s3_bucket.bucket_with_public_policy.arn}/*"
      }
    ]
  })
}

# Random suffix to ensure unique bucket names
resource "random_id" "bucket_suffix" {
  byte_length = 4
}
