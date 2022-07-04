# define a versão do terraform e os providers usados
terraform {
  required_providers {
    aws = {
       source = "hashicorp/aws" 
       version = "~> 4.16"
     }
  }
  required_version = ">= 1.2.0"
}

# configura o provider da aws
provider "aws" {
  region = "sa-east-1"
  profile = "terraform_user"
}
