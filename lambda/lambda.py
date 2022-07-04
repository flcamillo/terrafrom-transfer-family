import os
import json


# retorna a politica do usuário para acesso apenas em sua área no bucket
def user_policy(user):
    # define a policy em json
    policy = {
        "Policy": {
            "Version": "2012-10-17",
            "Statement":
            [
                {
                    "Resource": "arn:aws:s3:::*",
                    "Action": ["s3:PutObject",
                               "s3:GetObject",
                               "s3:DeleteObjectVersion",
                               "s3:DeleteObject",
                               "s3:GetObjectVersion",
                               "s3:GetObjectACL",
                               "s3:PutObjectACL"],
                    "Effect": "Allow",
                    "Sid": "HomeDirObjectAccess"
                },
                {
                    "Condition":
                    {
                        "StringLike":
                        {
                            "s3:prefix":
                            [
                                user + "/*",
                                user + "/"]
                        }
                    },
                    "Resource": "arn:aws:s3:::" + os.environ['S3_BUCKET'],
                    "Action": "s3:ListBucket",
                    "Effect": "Allow",
                    "Sid": "ListHomeDir"
                }
            ]
        }
    }
    # retorna o json em formato string
    return json.dumps(policy)


# realiza a autenticação do usuário
def auth_user(user, password):
    if (user == "fabio" and password == "teste"):
        auth = {
            "Role": os.environ['S3_ROLE'],
            "Policy": user_policy(user),
            "HomeDirectory": "/" + user,
        }
        return auth
    return None


# função principal da lambda
def lambda_handler(event, context):
    print(event)
    return auth_user(event["username"], event["password"])
