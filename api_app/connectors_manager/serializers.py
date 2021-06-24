from rest_framework import serializers
from django.conf import settings

import os
import json
import logging

from intel_owl import secrets as secrets_store
from .models import ConnectorReport

logger = logging.getLogger(__name__)

DATA_TYPE_MAPPING = {
    "number": (
        int,
        float,
    ),
    "string": str,
    "bool": bool,
}


class BaseField(serializers.Field):
    def to_representation(self, value):
        return value

    def to_internal_value(self, data):
        return data


class SecretSerializer(serializers.Serializer):
    """
    validation serializer for `secrets` of ConnectorConfigSerializer
    """

    TYPE_CHOICES = (
        ("number", "number"),
        ("string", "string"),
        ("bool", "bool"),
    )

    key_name = serializers.CharField(max_length=128)
    secret_name = serializers.CharField(max_length=128)
    type = serializers.ChoiceField(choices=TYPE_CHOICES)
    required = serializers.BooleanField()
    default = BaseField(allow_null=True, required=True)
    description = serializers.CharField(max_length=512)

    def validate(self, data):
        default, secret_type = data["default"], data["type"]
        if default is not None and type(default) is not type(secret_type):
            validation_error = {
                data["key_name"]: {
                    "default": f"should be of type {secret_type}, got {type(default)}"
                }
            }
            raise serializers.ValidationError(validation_error)
        return data


class ConnectorConfigSerializer(serializers.Serializer):
    """
    serializer for connectors from connector_config.json.
    """

    disabled = serializers.BooleanField()
    description = serializers.CharField(max_length=512)
    python_module = serializers.CharField(max_length=128)
    config = serializers.JSONField()
    secrets = serializers.JSONField()
    verification = serializers.SerializerMethodField()

    @classmethod
    def read_and_verify_config(cls):
        config_path = os.path.join(
            settings.BASE_DIR, "configuration", "connector_config.json"
        )
        with open(config_path) as f:
            connector_config = json.load(f)
            serializer_errors = {}
            for key, config in connector_config.items():
                serializer = cls(data=config)
                if serializer.is_valid():
                    connector_config[
                        key
                    ] = serializer.data  # mutate with processed config
                else:
                    serializer_errors[key] = serializer.errors

            if bool(serializer_errors):  # returns False if empty
                logger.error(f"connector config serializer failed: {serializer_errors}")
                return False, {}
            return True, connector_config

    def validate_secrets(self, secrets):
        data = [
            {"key_name": key, **secret_dict} for key, secret_dict in secrets.items()
        ]  # list comprehension + spread operator
        serializer = SecretSerializer(data=data, many=True)
        serializer.is_valid(raise_exception=True)
        return secrets

    def check_secrets(self, secrets):
        exceptions = {}
        for key_name, secret_dict in secrets.items():
            if secret_dict.get("required", False):
                # check if set and correct data type
                secret_val = secrets_store.get_secret(secret_dict["secret_name"])
                if not secret_val:
                    exceptions[key_name] = f"'{key_name}': not set"
                elif secret_val and not isinstance(
                    secret_val, DATA_TYPE_MAPPING[secret_dict["type"]]
                ):
                    exceptions[key_name] = "'%s': expected %s got %s" % (
                        key_name,
                        secret_dict["type"],
                        type(secret_val),
                    )
        return exceptions

    def get_verification(self, raw_instance):
        # raw instance because input is json and not django model object
        exceptions = self.check_secrets(raw_instance["secrets"])
        missing_secrets = list(exceptions.keys())
        final_err_msg = ";".join(exceptions.values())
        final_err_msg += "; (%d of %d satisfied)" % (
            len(missing_secrets),
            len(raw_instance["secrets"].keys()),
        )

        return {
            "configured": len(missing_secrets) == 0,
            "error_message": final_err_msg,
            "missing_secrets": missing_secrets,
        }


class ConnectorReportSerializer(serializers.ModelSerializer):
    """
    ConnectorReport model's serializer.
    """

    name = serializers.CharField(source="connector")
    success = serializers.SerializerMethodField()
    started_time_str = serializers.SerializerMethodField()

    class Meta:
        model = ConnectorReport
        fields = (
            "name",
            "success",
            "report",
            "errors",
            "process_time",
            "started_time_str",
        )

    def get_success(self, instance):
        if instance.status == "success":
            return True
        elif instance.status == "failure":
            return False

    def get_started_time_str(self, instance):
        return instance.start_time.strftime("%Y-%m-%d %H:%M:%S")
