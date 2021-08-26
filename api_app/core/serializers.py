# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import os
import sys
import json
import logging
import hashlib
from typing import List, TypedDict

from django.conf import settings
from rest_framework import serializers as rfs
from cache_memoize import cache_memoize

from intel_owl import secrets as secrets_store


logger = logging.getLogger(__name__)

DATA_TYPE_MAPPING = {
    "number": (
        int,
        float,
    ),
    "string": str,
    "bool": bool,
}


class ConfigVerificationType(TypedDict):
    configured: bool
    error_message: str
    missing_secrets: List[str]


class BaseField(rfs.Field):
    def to_representation(self, value):
        return value

    def to_internal_value(self, data):
        return data


class SecretSerializer(rfs.Serializer):
    """
    A base serializer class for validating `secrets`.
    Used for `analyzer_config.json` and `connector_config.json` files.
    """

    TYPE_CHOICES = (
        ("number", "number"),
        ("string", "string"),
        ("bool", "bool"),
    )

    key_name = rfs.CharField(max_length=128)
    env_var_key = rfs.CharField(max_length=128)
    type = rfs.ChoiceField(choices=TYPE_CHOICES)
    description = rfs.CharField(allow_blank=True, required=False, max_length=512)


class AbstractConfigSerializer(rfs.Serializer):
    """
    Abstract serializer for `analyzer_config.json` and `connector_config.json` files.
    """

    # constants
    CONFIG_FILE_NAME = ""

    # sentinel/ flag
    _is_valid_flag = False

    # common fields
    name = rfs.CharField(required=True)
    python_module = rfs.CharField(required=True, max_length=128)
    disabled = rfs.BooleanField(required=True)
    config = rfs.JSONField(required=True)
    secrets = rfs.JSONField(required=False)
    description = rfs.CharField(allow_blank=True, required=False)
    # automatically populated fields
    verification = rfs.SerializerMethodField()

    def is_valid(self, raise_exception=False):
        ret = super().is_valid(raise_exception=raise_exception)
        if ret:
            self._is_valid_flag = True
        return ret

    def get_verification(self, raw_instance) -> ConfigVerificationType:
        # raw instance because input is json and not django model object
        errors = self._check_secrets(raw_instance["secrets"])
        missing_secrets = list(errors.keys())
        num_missing_secrets = len(missing_secrets)
        num_total_secrets = len(raw_instance["secrets"].keys())
        final_err_msg = ";".join(errors.values())
        final_err_msg += "; (%d of %d satisfied)" % (
            num_total_secrets - num_missing_secrets,
            num_total_secrets,
        )

        return {
            "configured": num_missing_secrets == 0,
            "error_message": final_err_msg,
            "missing_secrets": missing_secrets,
        }

    def validate_secrets(self, secrets):
        # items in JSON file are in key-value format,
        # but we need a list of objects instead
        data = [
            {"key_name": key, **secret_dict} for key, secret_dict in secrets.items()
        ]
        serializer = SecretSerializer(data=data, many=True)
        serializer.is_valid(raise_exception=True)
        return secrets

    # utility methods
    def _check_secrets(self, secrets):
        errors = {}
        for key_name, secret_dict in secrets.items():
            # check if set and correct data type
            secret_val = secrets_store.get_secret(secret_dict["env_var_key"])
            if not secret_val:
                errors[key_name] = f"'{key_name}': not set"
            elif secret_val and not isinstance(
                secret_val, DATA_TYPE_MAPPING[secret_dict["type"]]
            ):
                errors[key_name] = "'%s': expected %s got %s" % (
                    key_name,
                    secret_dict["type"],
                    type(secret_val),
                )

        return errors

    @classmethod
    def _get_config_path(cls) -> str:
        """
        Returns full path to the config file.
        """
        return os.path.join(settings.BASE_DIR, "configuration", cls.CONFIG_FILE_NAME)

    @classmethod
    def _read_config(cls) -> dict:
        """
        Returns config file as `dict`.
        """
        config_path = cls._get_config_path()
        with open(config_path) as f:
            config_dict = json.load(f)
        return config_dict

    @classmethod
    def _md5_config_file(cls) -> str:
        """
        Returns md5sum of config file.
        """
        fpath = cls._get_config_path()
        with open(fpath, "r") as fp:
            buffer = fp.read().encode("utf-8")
            md5hash = hashlib.md5(buffer).hexdigest()
        return md5hash

    @classmethod
    @cache_memoize(
        timeout=sys.maxsize,
        args_rewrite=lambda cls: f"{cls.__name__}-{cls._md5_config_file()}",
    )
    def read_and_verify_config(cls) -> dict:
        """
        Returns verified config.
        This function is memoized for the md5sum of the JSON file.
        """
        config_dict = cls._read_config()
        serializer_errors = {}
        for key, config in config_dict.items():
            new_config = {"name": key, **config}
            serializer = cls(data=new_config)  # lgtm [py/call-to-non-callable]
            if serializer.is_valid():
                config_dict[key] = serializer.data
            else:
                serializer_errors[key] = serializer.errors

        if bool(serializer_errors):
            logger.error(f"{cls.__name__} serializer failed: {serializer_errors}")
            raise rfs.ValidationError(serializer_errors)

        return config_dict
