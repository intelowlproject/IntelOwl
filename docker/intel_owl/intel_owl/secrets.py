import boto3
import base64
import os
import logging

from botocore.exceptions import ClientError, NoCredentialsError


class RetrieveSecretException(Exception):
    pass


def aws_get_secret(secret_name):
    region_name = os.environ.get("AWS_REGION", "eu-central-1")
    secret = None

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager", region_name=region_name)

    # In this sample we only handle the specific exceptions..
    # ... for the 'GetSecretValue' API. See:
    # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "DecryptionFailureException":
            # Secrets Manager can't decrypt the protected secret text..
            # ... using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise RetrieveSecretException(e)
        if e.response["Error"]["Code"] == "InternalServiceErrorException":
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise RetrieveSecretException(e)
        if e.response["Error"]["Code"] == "InvalidParameterException":
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise RetrieveSecretException(e)
        if e.response["Error"]["Code"] == "InvalidRequestException":
            # You provided a parameter value that is not valid for the..
            # ... current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise RetrieveSecretException(e)
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise RetrieveSecretException(e)
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary,..
        # ... one of these fields will be populated.
        if "SecretString" in get_secret_value_response:
            secret = get_secret_value_response["SecretString"]
        else:
            secret = base64.b64decode(get_secret_value_response["SecretBinary"])

    return secret


def get_secret(secret_name):
    """
    first check the secret in the environment
    then try to find the secret in AWS Secret Manager
    """
    secret = os.environ.get(secret_name, "")
    aws_secrets = os.environ.get("AWS_SECRETS", False)
    if not secret and aws_secrets:
        try:
            secret = aws_get_secret(secret_name)
        except RetrieveSecretException as e:
            logging.error(f"Failed retrieving of secret {secret_name}. Error: {e}.")
        except NoCredentialsError as e:
            logging.error(f"Error: {e}. Secret: {secret_name}")

    return secret
