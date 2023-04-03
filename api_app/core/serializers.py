# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import List, Optional, TypedDict

from rest_framework import serializers as rfs

from api_app.core.models import AbstractConfig, AbstractReport
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
    """

    queue = rfs.CharField(required=True)
    soft_time_limit = rfs.IntegerField(required=True)


class _TypeSerializer(rfs.Serializer):
    type = rfs.ChoiceField(choices=list(PARAM_DATATYPE_CHOICES.keys()))
    description = rfs.CharField(allow_blank=True, required=True, max_length=512)
    default = BaseField(required=False)

    def validate(self, attrs):
        if "default" in attrs:
            default_type = type(attrs["default"]).__name__
            expected_type = attrs["type"]
            if default_type != expected_type:
                raise rfs.ValidationError(
                    f"Invalid default type. {default_type} != {expected_type}"
                )
        return super().validate(attrs)


class _ParamSerializer(_TypeSerializer):
    """
    To validate `params` attr.
    """

    default = BaseField(required=True)


class _SecretSerializer(_TypeSerializer):
    """
    To validate `secrets` attr.
    """

    required = rfs.BooleanField(required=True)


class AbstractConfigSerializer(rfs.ModelSerializer):

    secrets = rfs.DictField(
        child=_SecretSerializer(required=True), required=False, allow_empty=True
    )
    params = rfs.DictField(
        child=_ParamSerializer(required=True), required=False, allow_empty=True
    )
    config = _ConfigSerializer(required=True)

    class Meta:
        fields = rfs.ALL_FIELDS

    def to_representation(self, instance: AbstractConfig):
        user = self.context["request"].user
        result = super().to_representation(instance)
        result["verification"] = instance.get_verification(user)
        params_values = instance.read_params(user)
        for param, param_dict in result["params"].items():
            try:
                param_dict["value"] = params_values[param]
            except KeyError:
                param_dict["value"] = None
        result["disabled"] = not instance.is_runnable(user)
        return result

    def to_internal_value(self, data):
        raise NotImplementedError()


class AbstractReportSerializer(rfs.ModelSerializer):

    name = rfs.PrimaryKeyRelatedField(read_only=True, source="config")

    class Meta:
        fields = (
            "name",
            "process_time",
            "report",
            "status",
            "errors",
            "start_time",
            "end_time",
        )

    def to_representation(self, instance: AbstractReport):
        data = super().to_representation(instance)
        data["type"] = instance.config.type.label.lower()
        data["runtime_configuration"] = instance.runtime_configuration
        return data

    def to_internal_value(self, data):
        raise NotImplementedError()
