# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import os
import sys
import json
import logging
import hashlib
from typing import List, TypedDict, Optional

from django.conf import settings
from rest_framework import serializers as rfs
from cache_memoize import cache_memoize

from intel_owl import secrets as secrets_store
from intel_owl.consts import PARAM_DATATYPE_CHOICES


logger = logging.getLogger(__name__)


class ConfigVerificationType(TypedDict):
    configured: bool
    error_message: Optional[str]
    missing_secrets: List[str]


class BaseField(rfs.Field):
    def to_representation(self, value):
        return value

    def to_internal_value(self, data):
        return data


class _ConfigSerializer(rfs.Serializer):
    """
    To validate `config` attr.
    Used for `analyzer_config.json` and `connector_config.json` files.
    """

    queue = rfs.CharField(required=True)
    soft_time_limit = rfs.IntegerField(required=True)


class _ParamSerializer(rfs.Serializer):
    """
    To validate `params` attr.
    Used for `analyzer_config.json` and `connector_config.json` files.
    """

    value = BaseField()
    type = rfs.ChoiceField(choices=PARAM_DATATYPE_CHOICES)
    description = rfs.CharField(allow_blank=True, required=True, max_length=512)

    def validate(self, attrs):
        value_type = type(attrs["value"]).__name__
        expected_type = attrs["type"]
        if value_type != expected_type:
            raise rfs.ValidationError(
                f"Invalid value type. {value_type} != {expected_type}"
            )
        return super().validate(attrs)


class _SecretSerializer(rfs.Serializer):
    """
    To validate `secrets` attr.
    Used for `analyzer_config.json` and `connector_config.json` files.
    """

    env_var_key = rfs.CharField(required=True, max_length=128)
    description = rfs.CharField(required=True, allow_blank=True, max_length=512)
    required = rfs.BooleanField(required=True)


class AbstractConfigSerializer(rfs.Serializer):
    """
    Abstract serializer for `analyzer_config.json` and `connector_config.json` files.
    """

    # constants
    CONFIG_FILE_NAME = ""

    # sentinel/ flag
    _is_valid_flag = False

    # common basic fields
    name = rfs.CharField(required=True)
    python_module = rfs.CharField(required=True, max_length=128)
    disabled = rfs.BooleanField(required=True)
    description = rfs.CharField(allow_blank=True, required=False)
    # common custom fields
    config = _ConfigSerializer()
    secrets = rfs.DictField(child=_SecretSerializer())
    params = rfs.DictField(child=_ParamSerializer())
    # automatically populated fields
    verification = rfs.SerializerMethodField()

    def is_valid(self, raise_exception=False):
        ret = super().is_valid(raise_exception=raise_exception)
        if ret:
            self._is_valid_flag = True
        return ret

    def get_verification(self, raw_instance: dict) -> ConfigVerificationType:
        # raw instance because input is json and not django model object
        # get all missing secrets
        secrets = raw_instance["secrets"]
        missing_secrets = []
        for s_key, s_dict in secrets.items():
            # check if available in environment
            secret_val = secrets_store.get_secret(s_dict["env_var_key"], default=None)
            if not secret_val and s_dict["required"]:
                missing_secrets.append(s_key)

        num_missing_secrets = len(missing_secrets)
        if num_missing_secrets:
            configured = False
            num_total_secrets = len(secrets.keys())
            error_message = "(%s) not set; (%d of %d satisfied)" % (
                ",".join(missing_secrets),
                num_total_secrets - num_missing_secrets,
                num_total_secrets,
            )
        else:
            configured = True
            error_message = None

        return {
            "configured": configured,
            "error_message": error_message,
            "missing_secrets": missing_secrets,
        }

    # utility methods

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
