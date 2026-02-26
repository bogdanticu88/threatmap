resource "aws_s3_bucket" "mfa_test" {
  bucket = "mfa-delete-test"

  versioning {
    enabled = true
  }
}
