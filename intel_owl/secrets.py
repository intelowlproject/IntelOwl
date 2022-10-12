# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import base64
import logging
import os

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from django.core.exceptions import AppRegistryNotReady


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


def get_secret(secret_name, default="", plugin_type=None, plugin_name=None):
    """
    first check the secret in the environment
    then try to find the secret in AWS Secret Manager
    """
    secret = default
    try:
        from api_app.models import PluginConfig

        query = {
            "attribute": secret_name,
        }
        if plugin_type:
            query["type"] = plugin_type
        if plugin_name:
            query["plugin_name"] = plugin_name

        if PluginConfig.objects.filter(
            **query, config_type=PluginConfig.ConfigType.SECRET
        ).exists():
            secret = PluginConfig.objects.get(
                **query, config_type=PluginConfig.ConfigType.SECRET
            ).value
    except AppRegistryNotReady:
        # This is a Django env var, not analyzer var
        pass
    if secret == default:
        secret = os.environ.get(secret_name, default)
    aws_secrets_enabled = os.environ.get("AWS_SECRETS", False) == "True"
    if not secret and aws_secrets_enabled:
        try:
            secret = aws_get_secret(secret_name)
        except RetrieveSecretException as e:
            logging.error(
                f"Failed retrieving of secret {secret_name}. Error: {e}."
            )  # lgtm [py/clear-text-logging-sensitive-data]
        except NoCredentialsError as e:
            logging.error(
                f"Error: {e}. Secret: {secret_name}"
            )  # lgtm [py/clear-text-logging-sensitive-data]

    return secret
