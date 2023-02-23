# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import List, Optional, TypedDict

from rest_framework import serializers as rfs

from api_app.core.models import AbstractConfig
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


class _ParamSerializer(rfs.Serializer):
    """
    To validate `params` attr.
    """

    value = BaseField()
    type = rfs.ChoiceField(choices=list(PARAM_DATATYPE_CHOICES.keys()))
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
    """

    env_var_key = rfs.CharField(required=True, max_length=128)
    description = rfs.CharField(required=True, allow_blank=True, max_length=512)
    required = rfs.BooleanField(required=True)
    type = rfs.ChoiceField(choices=list(PARAM_DATATYPE_CHOICES.keys()), required=True)
    default = BaseField(required=False)

    def validate(self, attrs):
        if "type" in attrs and "default" in attrs:
            default_type = type(attrs["default"]).__name__
            expected_type = attrs["type"]
            if default_type != expected_type:
                raise rfs.ValidationError(
                    f"Invalid default type. {default_type} != {expected_type}"
                )
        return super().validate(attrs)


class AbstractConfigSerializer(rfs.ModelSerializer):

    secrets = rfs.DictField(
        child=_SecretSerializer(required=True), required=False, allow_empty=True
    )
    params = rfs.DictField(
        child=_ParamSerializer(required=True), required=False, allow_empty=True
    )
    config = _ConfigSerializer(required=True)

    class Meta:
        model = AbstractConfig
        fields = rfs.ALL_FIELDS

    def to_representation(self, instance: AbstractConfig):
        from api_app.models import OrganizationPluginState, PluginConfig

        user = self.context["request"].user
        result = super().to_representation(instance)
        result["verification"] = instance.get_verification(user)

        for param, param_dict in result["params"].items():
            try:
                param_dict["value"] = PluginConfig.visible_for_user(user).get(
                    type=self.Meta.model._get_type(),
                    attribute=param,
                    config_type=PluginConfig.ConfigType.PARAMETER,
                    plugin_name=instance.name,
                )
            except PluginConfig.DoesNotExist:
                param_dict["value"] = None
        if user.has_membership():
            try:
                disabled = OrganizationPluginState.objects.get(
                    organization=user.membership.organization,
                    type=self.Meta.model._get_type(),
                    plugin_name=instance.name,
                )
            except OrganizationPluginState.DoesNotExist:
                pass
            else:
                if disabled:
                    result["disabled"] = disabled

        return result
