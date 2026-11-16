locals {
  # Built from the variable instead of aws_s3_bucket.this.arn on purpose.
  # The bucket's ARN attribute is unknown until apply, which would make the
  # whole policy document unknown in the plan and impossible to check in CI.
  bucket_arn = "arn:aws:s3:::${var.bucket_name}"
}

# Role for an application running on EC2 that needs the bucket.
resource "aws_iam_role" "app" {
  name = "${var.project_name}-app"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

# Least privilege: list this one bucket, read and write its objects.
resource "aws_iam_role_policy" "app_bucket_access" {
  name = "bucket-access"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListBucket"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = local.bucket_arn
      },
      {
        Sid      = "ReadWriteObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "${local.bucket_arn}/*"
      },
    ]
  })
}
