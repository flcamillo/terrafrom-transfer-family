variable "lambda_root" {
  type        = string
  description = "Caminho para a pasta onde está todo o conteúdo da lambda"
  default     = "../lambda"
}

variable "lambda_auth_name" {
  type        = string
  description = "Nome da lambda de autenticação"
  default     = "transfer-family-auth"
}

variable "s3_bucket" {
  type        = string
  description = "Nome do bucket usado pelo transfer family"
  default     = "flc-transfer-family"
}

variable "vpc_id" {
  type        = string
  description = "Identificação da VPC para configurar o servidor do transfer family"
  default     = "vpc-ab1111cc"
}

variable "subnet_ids" {
  type        = list
  description = "Identificação da subnet para configurar o servidor do transfer family"
  default     = ["subnet-7beb561d"]
}
