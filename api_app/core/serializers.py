# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import List

from rest_framework import serializers as rfs

from api_app.core.models import AbstractConfig, AbstractReport, Parameter, ParameterConfig

logger = logging.getLogger(__name__)

class _ConfigSerializer(rfs.Serializer):
    """
    To validate `config` attr.
    """

    queue = rfs.CharField(required=True)
    soft_time_limit = rfs.IntegerField(required=True)

class ParamListSerializer(rfs.ListSerializer):

    def to_representation(self, data):
        result = super().to_representation(data)
        return {
            elem.pop("name"): elem for elem in result
        }

class ParamSerializer(rfs.ModelSerializer):
    class Meta:
        model = Parameter
        fields = rfs.ALL_FIELDS

    description = rfs.CharField(write_only=True)

    def to_representation(self, instance: Parameter):
        result = super().to_representation(instance)
        result["value"] = instance.get_first_value(self.context["request"].user).value
        return result

class ParamConfigSerializer(rfs.ModelSerializer):
    class Meta:
        model = ParameterConfig
        fields = rfs.ALL_FIELDS
    list_serializer_class = ParamListSerializer
    parameter = ParamSerializer(read_only=True)

    def to_representation(self, instance: ParameterConfig):
        result = super().to_representation(instance)
        result = result["parameter"]
        return result

class AbstractConfigSerializer(rfs.ModelSerializer):

    config = _ConfigSerializer(required=True)
    params = ParamConfigSerializer(read_only=True, many=True, source="parameters")
    secrets = ParamConfigSerializer(read_only=True, many=True, source="parameters")
    parameters = ParamConfigSerializer(write_only=True, many=True)

    class Meta:
        fields = rfs.ALL_FIELDS

    def validate_params(self, params:List[Parameter]):
        return [param for param in params if not param.is_secret]

    def validate_secrets(self, secrets: List[Parameter]):
        return [secret for secret in secrets if secret.is_secret]

    def to_representation(self, instance: AbstractConfig):
        user = self.context["request"].user
        result = super().to_representation(instance)
        result["verification"] = instance.get_verification(user)
        result["disabled"] = not instance.is_runnable(user)
        return result

    def to_internal_value(self, data):
        raise NotImplementedError()


class AbstractReportSerializer(rfs.ModelSerializer):

    name = rfs.PrimaryKeyRelatedField(read_only=True, source="config")

    class Meta:
        fields = (
            "id",
            "name",
            "process_time",
            "report",
            "status",
            "errors",
            "start_time",
            "end_time",
            "runtime_configuration",
        )


    def to_representation(self, instance: AbstractReport):
        data = super().to_representation(instance)
        data["type"] = instance.__class__.__name__.replace("Report", "").lower()
        return data

    def to_internal_value(self, data):
        raise NotImplementedError()
