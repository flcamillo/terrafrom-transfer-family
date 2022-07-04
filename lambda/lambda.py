import os
import json


# retorna a politica do usuário para acesso apenas em sua área no bucket
def user_policy(user):
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
                    "arn:aws:s3:::${transfer:HomeBucket}"
                ],
                "Condition": {
                    "StringLike": {
                        "s3:prefix": [
                            "${transfer:HomeFolder}/*",
                            "${transfer:HomeFolder}"
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
                "Resource": "arn:aws:s3:::${transfer:HomeDirectory}/*"
            }
        ]
    }
    # retorna o json em formato string
    return json.dumps(policy)


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
    print(os.environ['S3_ROLE'])
    print(os.environ['S3_BUCKET'])
    return auth_user(event["username"], event["password"])
