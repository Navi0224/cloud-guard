# DELIBERATELY INSECURE example - for testing cloud-guard only. Do not apply.
# Note: there is no aws_cloudtrail anywhere in this directory -> TF-CT-001.

# TF-IAM-001: wildcard policy written with jsonencode()
resource "aws_iam_policy" "god_mode" {
  name = "god-mode"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# TF-IAM-001: wildcard inline user policy written as a heredoc
resource "aws_iam_user_policy" "legacy_admin" {
  name = "legacy-admin"
  user = "legacy-user"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["*"], "Resource": ["*"] }
  ]
}
EOF
}

# TF-IAM-001: wildcard in a policy document data source
data "aws_iam_policy_document" "too_broad" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}
