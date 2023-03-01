from intel_owl import secrets

# AWS settings
AWS_IAM_ACCESS = secrets.get_secret("AWS_IAM_ACCESS", False) == "True"
if not AWS_IAM_ACCESS:
    AWS_ACCESS_KEY_ID = secrets.get_secret("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = secrets.get_secret("AWS_SECRET_ACCESS_KEY")
AWS_SECRETS = secrets.get_secret("AWS_SECRETS", False) == "True"
AWS_SQS = secrets.get_secret("AWS_SQS", False) == "True"
AWS_REGION = secrets.get_secret("AWS_REGION", "eu-central-1")

AWS_RDS_IAM_ROLE = secrets.get_secret("AWS_RDS_IAM_ROLE", False) == "True"
