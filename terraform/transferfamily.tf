# define a trusted policy do transfer family
data "aws_iam_policy_document" "transfer-family-trusted-policy-doc" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["transfer.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

# cria a role do transfer family com a trusted policy
resource "aws_iam_role" "role-transfer-family" {
  name               = "role-transfer-family-server"
  assume_role_policy = data.aws_iam_policy_document.transfer-family-trusted-policy-doc.json
}

# define a policy de acesso do transfer family
data "aws_iam_policy_document" "transfer-family-policy-doc" {
  statement {
    effect    = "Allow"
    resources = ["arn:aws:logs:*:*:*"]
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents"
    ]
  }
}

# cria a policy do transfer family com os acessos definidos
resource "aws_iam_policy" "policy-transfer-family" {
  name        = "policy-transfer-family"
  policy      = data.aws_iam_policy_document.transfer-family-policy-doc.json
  path        = "/"
  description = "Policy de acesso para o Transfer Family"
}

# associa a role com a policy
resource "aws_iam_role_policy_attachment" "attach-role-transfer-family" {
  role       = aws_iam_role.role-transfer-family.name
  policy_arn = aws_iam_policy.policy-transfer-family.arn
}

# cria o servidor do transfer family
resource "aws_transfer_server" "transfer-family-server" {
  endpoint_type = "PUBLIC"
  #endpoint_details {
  #  vpc_id     = var.vpc_id
  #  subnet_ids = var.subnet_ids
  #}
  protocols              = ["SFTP"]
  identity_provider_type = "AWS_LAMBDA"
  function               = aws_lambda_function.lambda-auth.arn
  logging_role           = aws_iam_role.role-transfer-family.arn
  tags = {
    Name = "transfer-server"
  }
}
