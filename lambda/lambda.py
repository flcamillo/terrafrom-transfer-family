import os
import json
import boto3

# cria o client para acesso ao kms
kms_client = boto3.client('secretsmanager')


# retorna a politica do usuário para acesso apenas em sua área no bucket
def user_policy(bucket, user):
    # define a policy em json
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowListingOfUserFolder",
                "Action": [
                    "s3:ListBucket"
                ],
                "Effect": "Allow",
                "Resource": [
                    "arn:aws:s3:::" + bucket
                ],
                "Condition": {
                    "StringLike": {
                        "s3:prefix": [
                            user + "/*",
                            user,
                        ]
                    }
                }
            },
            {
                "Sid": "HomeDirObjectAccess",
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:DeleteObject",
                    "s3:DeleteObjectVersion",
                    "s3:GetObjectVersion",
                    "s3:GetObjectACL",
                    "s3:PutObjectACL"
                ],
                "Resource": "arn:aws:s3:::" + bucket + "/" + user + "/*"
            }
        ]
    }
    # retorna o json em formato string
    return json.dumps(policy)


# utiliza o KMS para autenticar o usuário
# o id do segredo deve ser registrado como:
# transferfamily/users/user
#
# o segredo deve estar no formato json:
# {"password": "minha senha", "role": "arn da role", "policy": "json da policy", "sshkeys": "json da policy"}
#
# caso não exista os campos da role e policy então será usado o padrão
def auth_user_kms(user, password, server, protocol):
    # define o caminho do segredo no KMS
    # este caminho pode ser customizado de diversas formas para por exemplo
    # seprar os usuários por grupo, ou por servidor do transfer family, etc
    secret = "transferfamily/users/{0}".format(user)
    # recupera o segredo
    response = kms_client.get_secret_value(SecretId=secret)
    if response is None:
        print("ERROR no secret returned by KMS")
        return None
    # converte o segredo para JSON
    secrets = json.loads(response["SecretString"])
    # mapeia o diretório virtual do usuário
    virtualDirectory = [
        {
            "Entry": "/",
            "Target": "/{0}/{1}".format(os.environ['S3_BUCKET'], user),
        }
    ]
    # define o retorno padrão da autenticação
    auth = {
        "Role": os.environ['S3_ROLE'],
        "Policy": user_policy(os.environ['S3_BUCKET'], user),
        # "HomeDirectory": "/{0}/{1}".format(os.environ['S3_BUCKET'], user),
        "HomeDirectoryType": "LOGICAL",
        "HomeDirectoryDetails": json.dumps(virtualDirectory),
    }
    # se houver role customizada então substitui o default usado
    newRole = secrets.get("role")
    if newRole is not None and newRole != "":
        auth["Role"] = newRole
    # se houver politica customizada então substitui o default usado
    newPolicy = secrets.get("policy")
    if newPolicy is not None and newPolicy != "":
        auth["Policy"] = newPolicy
    # faz a autenticação da senha
    if secrets.get("password") == password:
        return auth
    # o transfer family não suporta duplo fator de autenticação, ou seja
    # usuário e senha + chave publica ssh
    # dessa forma, caso a senha esteja vazia procura a chave ssh do
    # usuário para retornar ao servidor
    if (password is None or password == "") and protocol == "SFTP":
        sshKeys = secrets.get("sshkeys")
        if sshKeys is not None and sshKeys != "":
            sshKeys.replace(",", ";")
            keyList = sshKeys.split(";")
            for n in range(len(keyList)):
                keyList[n] = keyList[n].strip()
            auth["PublicKeys"] = keyList
            return auth
        # gera log caso não exista chave ssh
        print("ERROR no ssh key found for user {1} from server {2}".format(
            user, server))
    # se não conseguiu autenticar loga o motivo e retorna
    print("ERROR invalid password for {0} user {1} from server {2}".format(
        protocol, user, server))
    return None


# realiza a autenticação do usuário
def auth_user(user, password):
    if (user == "fabio" and password == "teste"):
        # a policy do usuário precisa ser ajustada caso tenha / no final do diretório:
        # com barra o recurso ficaria: arn:aws:s3:::${transfer:HomeDirectory}*
        # sem barra o recurso ficaria: arn:aws:s3:::${transfer:HomeDirectory}/*
        auth = {
            "Role": os.environ['S3_ROLE'],
            "Policy": user_policy(user),
            "HomeDirectory": "/{0}/{1}".format(os.environ['S3_BUCKET'], user),
        }
        return auth
    return None


# função principal da lambda
def lambda_handler(event, context):
    print(event)
    # exibe o que foi usado
    print("Using S3 Role ARN: {0}".format(os.environ['S3_ROLE']))
    print("Using S3 Bucket Name: {0}".format(os.environ['S3_BUCKET']))
    # identifica os metadados do evento
    user = event.get("username")
    password = event.get("password")
    server = event.get("serverId")
    address = event.get("sourceIp")
    protocol = event.get("protocol")
    # caso não tenha sido informado o usuário rejeita a conexão
    if user is None or user == "":
        print("ERROR user not provided")
        return None
    # caso não tenha sido informado o id do servidor do transfer family
    # tambem rejeita a conexão, essa situação não é esperada
    if server is None or server == "":
        print("ERROR server id not provided")
        return None
    # return auth_user(user, password)
    return auth_user_kms(user, password, server, protocol)
