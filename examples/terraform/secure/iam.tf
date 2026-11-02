# Least-privilege IAM: specific actions on specific resources.

resource "aws_iam_policy" "uploads_read" {
  name = "uploads-read"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = ["arn:aws:s3:::example-user-uploads", "arn:aws:s3:::example-user-uploads/*"]
    }]
  })
}

data "aws_iam_policy_document" "deploy" {
  statement {
    actions   = ["ecs:UpdateService", "ecs:DescribeServices"]
    resources = ["arn:aws:ecs:eu-central-1:111122223333:service/prod/*"]
  }

  # A wildcard DENY is a guard rail, not a risk - cloud-guard must not flag it.
  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_iam_role_policy" "deploy" {
  name   = "deploy"
  role   = "deploy-role"
  policy = data.aws_iam_policy_document.deploy.json
}
