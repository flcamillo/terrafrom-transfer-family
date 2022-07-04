# define a trusted policy para os usuários do bucket
data "aws_iam_policy_document" "bucket-access-trusted-policy-doc" {
  statement {
    effect = "Allow"
    principals {
      type = "Service"
      identifiers = [
        "transfer.amazonaws.com"
      ]
    }
    actions = ["sts:AssumeRole"]
  }
}

# cria a role para os usuários do bucket com a trusted policy
resource "aws_iam_role" "role-bucket-access-trusted" {
  name               = "role-transfer-family-users"
  assume_role_policy = data.aws_iam_policy_document.bucket-access-trusted-policy-doc.json
}

# define a policy de acesso do bucket
data "aws_iam_policy_document" "bucket-access-policy-doc" {
  statement {
    effect    = "Allow"
    resources = ["${aws_s3_bucket.transfer-family-root.arn}"]
    actions = [
      "s3:ListBucket"
    ]
  }
  statement {
    effect    = "Allow"
    resources = ["${aws_s3_bucket.transfer-family-root.arn}/*"]
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
      "s3:GetBucketLocation",
      "s3:GetObjectVersion",
      "s3:GetObjectACL",
      "s3:PutObjectACL",
    ]
  }
}

# cria a policy da lambda com os acessos definidos
resource "aws_iam_policy" "policy-bucket-access" {
  name        = "policy-transfer-family-users"
  policy      = data.aws_iam_policy_document.bucket-access-policy-doc.json
  path        = "/"
  description = "Policy de acesso para os usuários do bucket"
}

# associa a role com a policy
resource "aws_iam_role_policy_attachment" "attach-role-bucket-access" {
  role       = aws_iam_role.role-bucket-access-trusted.name
  policy_arn = aws_iam_policy.policy-bucket-access.arn
}

# cria o bucket que será usado pelo transfer family
resource "aws_s3_bucket" "transfer-family-root" {
  bucket = var.s3_bucket
}

# configura o bucket para privado
resource "aws_s3_bucket_acl" "transfer-family-root-acl" {
  bucket = aws_s3_bucket.transfer-family-root.id
  acl    = "private"
}
