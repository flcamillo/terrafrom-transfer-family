# define a trusted policy da lambda
data "aws_iam_policy_document" "lambda-auth-trusted-policy-doc" {
  statement {
    effect = "Allow"
    principals {
      type = "Service"
      identifiers = [
        "lambda.amazonaws.com"
      ]
    }
    actions = ["sts:AssumeRole"]
  }
}

# cria a role da lambda com a trusted policy
resource "aws_iam_role" "role-lambda-auth" {
  name               = "role-transfer-family-auth"
  assume_role_policy = data.aws_iam_policy_document.lambda-auth-trusted-policy-doc.json
}

# define a policy de acesso da lambda
data "aws_iam_policy_document" "lambda-auth-policy-doc" {
  statement {
    effect    = "Allow"
    resources = ["arn:aws:logs:*:*:*"]
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
  }
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "secretsmanager:GetSecretValue"
    ]
  }
}

# cria a policy da lambda com os acessos definidos
resource "aws_iam_policy" "policy-lambda-auth" {
  name        = "policy-transfer-family-auth"
  policy      = data.aws_iam_policy_document.lambda-auth-policy-doc.json
  path        = "/"
  description = "Policy de acesso para a Lambda de Autenticação"
}

# associa a role com a policy
resource "aws_iam_role_policy_attachment" "attach-role-lambda-auth" {
  role       = aws_iam_role.role-lambda-auth.name
  policy_arn = aws_iam_policy.policy-lambda-auth.arn
}

# instala as dependências da lambda
resource "null_resource" "install_dependencies" {
  provisioner "local-exec" {
    command = "pip install -r ${var.lambda_root}/requirements.txt -t ${var.lambda_root}/"
  }
  triggers = {
    dependencies_versions = filemd5("${var.lambda_root}/requirements.txt")
    source_versions       = filemd5("${var.lambda_root}/lambda.py")
  }
}

# da permissão de execução na lambda para o transfer family
resource "aws_lambda_permission" "allow-transfer-family" {
  statement_id  = "allow-transfer-family-invokation"
  action        = "lambda:InvokeFunction"
  principal     = "transfer.amazonaws.com"
  function_name = aws_lambda_function.lambda-auth.function_name
  source_arn    = aws_transfer_server.transfer-family-server.arn
}

# cria um nome de arquivo único para esta versão dos arquivos da lambda
# se os arquivos forem modificados será gerado um novo id para o mesmo
resource "random_uuid" "lambda_src_hash" {
  keepers = {
    for filename in setunion(
      fileset(var.lambda_root, "lambda.py"),
      fileset(var.lambda_root, "requirements.txt")
    ) :
    filename => filemd5("${var.lambda_root}/${filename}")
  }
}

# cria um arquivo zip com o conteúdo da lambda
# antes de criar o zip deve instalar todas as dependências da lambda
data "archive_file" "lambda_source" {
  depends_on = [null_resource.install_dependencies]
  excludes = [
    "__pycache__",
    "venv",
  ]
  source_dir  = var.lambda_root
  output_path = "${random_uuid.lambda_src_hash.result}.zip"
  type        = "zip"
}

# cria o loggroup do cloudwatch para a lambda
resource "aws_cloudwatch_log_group" "lambda-auth-log-group" {
  name              = "/aws/lambda/${aws_lambda_function.lambda-auth.function_name}"
  retention_in_days = 7
}

# define a lambda
resource "aws_lambda_function" "lambda-auth" {
  function_name    = var.lambda_auth_name
  handler          = "lambda.lambda_handler"
  runtime          = "python3.8"
  role             = aws_iam_role.role-lambda-auth.arn
  filename         = data.archive_file.lambda_source.output_path
  source_code_hash = data.archive_file.lambda_source.output_base64sha256
  environment {
    variables = {
      S3_BUCKET = aws_s3_bucket.transfer-family-root.bucket
      S3_ROLE   = aws_iam_role.role-bucket-access-trusted.arn
    }
  }
}
