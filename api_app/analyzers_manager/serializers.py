# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import serializers as rfs
from django.conf import settings

import os
import json
import logging

from .models import AnalyzerReport
from ..helpers import map_data_type

from intel_owl.secrets import get_secret


logger = logging.getLogger(__name__)


class BaseField(rfs.Field):
    def to_representation(self, value):
        return value

    def to_internal_value(self, data):
        return data


class AnalyzerReportSerializer(rfs.ModelSerializer):
    class Meta:
        model = AnalyzerReport
        fields = "__all__"


class AnalyzerConfigSerializer(rfs.Serializer):
    TYPE_CHOICES = (
        ("file", "file"),
        ("observable", "observable"),
    )
    HASH_CHOICES = (
        ("md5", "md5"),
        ("sha256", "sha256"),
    )

    # Required fields
    name = rfs.CharField(required=True)
    type = rfs.ChoiceField(required=True, choices=TYPE_CHOICES)
    python_module = rfs.CharField(required=True)
    disabled = rfs.BooleanField(required=True)
    external_service = rfs.BooleanField(required=True)
    config = rfs.JSONField(required=True)
    # Optional Fields
    secrets = rfs.JSONField(required=False)
    description = rfs.CharField(allow_blank=True, required=False)
    leaks_info = rfs.BooleanField(required=False)
    run_hash = rfs.BooleanField(required=False)
    run_hash_type = rfs.ChoiceField(required=False, choices=HASH_CHOICES)
    supported_filetypes = rfs.ListField(required=False)
    not_supported_filetypes = rfs.ListField(required=False)
    observable_supported = rfs.ListField(required=False)
    # Automatically Populated Fields
    verification = rfs.SerializerMethodField()

    @classmethod
    def read_and_verify_config(cls):
        config_path = os.path.join(
            settings.BASE_DIR, "configuration", "analyzer_config.json"
        )
        with open(config_path) as f:
            analyzers_config = json.load(f)
            serializer_errors = {}
            for key, config in analyzers_config.items():
                new_config = {"name": key, **config}
                serializer = cls(data=new_config)
                if serializer.is_valid():
                    analyzers_config[key] = serializer.data
                else:
                    serializer_errors[key] = serializer.errors

            if bool(serializer_errors):
                logger.error(f"analyzer config serializer failed: {serializer_errors}")
                raise rfs.ValidationError(serializer_errors)

            return analyzers_config

    def validate_secrets(self, secrets):
        data = [
            {"key_name": key, **secret_dict} for key, secret_dict in secrets.items()
        ]

        serializer = SecretSerializer(data=data, many=True)
        serializer.is_valid(raise_exception=True)

        return secrets

    def check_secrets(self, secrets):
        errors = {}

        for name, conf in secrets.items():
            if conf.get("required", False):
                secret = get_secret(conf["env_var_key"])
                if not secret:
                    errors[name] = f"'{name}': not set"
                elif not isinstance(secret, map_data_type(conf["type"])):
                    errors[
                        name
                    ] = f"'{name}': expected {conf['type']}, got {type(secret)}"

        return errors

    def get_verification(self, config):
        errors = self.check_secrets(config["secrets"])
        missing_secrets = list(errors.keys())
        tooltip_error_msg = ";".join(errors.values())
        tooltip_error_msg += (
            f", ({len(missing_secrets)} of {len(config['secrets'])} satisfied)"
        )

        verified = {
            "configured": len(missing_secrets) == 0,
            "error_message": tooltip_error_msg,
            "missing_secrets": missing_secrets,
        }

        return verified


class SecretSerializer(rfs.Serializer):
    TYPE_CHOICES = (
        ("number", "number"),
        ("string", "string"),
        ("bool", "bool"),
    )

    key_name = rfs.CharField(required=True, max_length=128)
    env_var_key = rfs.CharField(required=True, max_length=128)
    type = rfs.ChoiceField(required=True, choices=TYPE_CHOICES)
    required = rfs.BooleanField(required=True)
    default = BaseField(allow_null=True, required=True)
    description = rfs.CharField(allow_blank=True, required=False, max_length=512)

    def validate(self, data):
        default, secret_type = data["default"], data["type"]
        if default is not None and type(default) is not type(secret_type):
            validation_error = {
                data["key_name"]: {
                    "default": f"should be of type {secret_type}, got {type(default)}"
                }
            }
            raise rfs.ValidationError(validation_error)
        return data
