import json
import logging
from typing import Any

from django.core.cache import cache
from rest_framework import serializers as rfs
from rest_framework.exceptions import ValidationError
from rest_framework.fields import SerializerMethodField

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.ingestors_manager.models import IngestorConfig
from api_app.models import Parameter, PluginConfig, PythonConfig, PythonModule
from api_app.serializers import ModelWithOwnershipSerializer
from api_app.serializers.celery import CrontabScheduleSerializer
from api_app.visualizers_manager.models import VisualizerConfig
from certego_saas.apps.user.models import User

logger = logging.getLogger(__name__)


class PluginConfigSerializer(ModelWithOwnershipSerializer):
    class Meta:
        model = PluginConfig
        fields = (
            "attribute",
            "config_type",
            "type",
            "plugin_name",
            "value",
            "owner",
            "organization",
            "id",
        )

    class CustomValueField(rfs.JSONField):
        def to_internal_value(self, data):
            if not data:
                raise ValidationError({"detail": "Empty insertion"})
            logger.info(f"verifying that value {data} ({type(data)}) is JSON compliant")
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                try:
                    data = json.dumps(data)
                    return json.loads(data)
                except json.JSONDecodeError:
                    logger.info(f"value {data} ({type(data)}) raised ValidationError")
                    raise ValidationError({"detail": "Value is not JSON-compliant."})

        def get_attribute(self, instance: PluginConfig):
            # We return `redacted` when
            # 1) is a secret AND
            # 2) is a value for the organization AND
            # (NOR OPERATOR)
            # 3) we are not its owner OR
            # 4) we are not an admin of the same organization
            if (
                instance.is_secret()
                and instance.for_organization
                and not (
                    self.context["request"].user.pk == instance.owner.pk
                    or (
                        self.context["request"].user.has_membership()
                        and self.context["request"].user.membership.organization.pk
                        == instance.owner.membership.organization.pk
                        and self.context["request"].user.membership.is_admin
                    )
                )
            ):
                return "redacted"
            return super().get_attribute(instance)

        def to_representation(self, value):
            result = super().to_representation(value)
            if isinstance(result, (list, dict)):
                return json.dumps(result)
            return result

    type = rfs.ChoiceField(choices=["1", "2", "3", "4"])  # retrocompatibility
    config_type = rfs.ChoiceField(choices=["1", "2"])  # retrocompatibility
    attribute = rfs.CharField()
    plugin_name = rfs.CharField()
    value = CustomValueField()

    def validate_value_type(self, value: Any, parameter: Parameter):
        if type(value).__name__ != parameter.type:
            raise ValidationError(
                {
                    "detail": f"Value has type {type(value).__name__}"
                    f" instead of {parameter.type}"
                }
            )

    def validate(self, attrs):
        if self.partial:
            # we are in an update
            return attrs
        _value = attrs["value"]
        # retro compatibility
        _type = attrs.pop("type")
        _config_type = attrs.pop("config_type")
        _plugin_name = attrs.pop("plugin_name")
        _attribute = attrs.pop("attribute")
        if _type == "1":
            class_ = AnalyzerConfig
        elif _type == "2":
            class_ = ConnectorConfig
        elif _type == "3":
            class_ = VisualizerConfig
        elif _type == "4":
            class_ = IngestorConfig
        else:
            raise RuntimeError("Not configured")
        # we set the pointers allowing retro-compatibility from the frontend
        config = class_.objects.get(name=_plugin_name)
        parameter = config.parameters.get(
            name=_attribute, is_secret=_config_type == "2"
        )
        self.validate_value_type(_value, parameter)

        attrs["parameter"] = parameter
        attrs[class_.snake_case_name] = config
        return super().validate(attrs)

    def update(self, instance, validated_data):
        self.validate_value_type(validated_data["value"], instance.parameter)
        return super().update(instance, validated_data)

    def to_representation(self, instance: PluginConfig):
        result = super().to_representation(instance)
        result["organization"] = (
            instance.organization.name if instance.organization is not None else None
        )
        return result


class ParamListSerializer(rfs.ListSerializer):
    @property
    def data(self):
        # this is to return a dict instead of a list
        return super(rfs.ListSerializer, self).data

    def to_representation(self, data):
        result = super().to_representation(data)
        return {elem.pop("name"): elem for elem in result}


class ParameterSerializer(rfs.ModelSerializer):
    value = SerializerMethodField()

    class Meta:
        model = Parameter
        fields = ["name", "type", "description", "required", "value", "is_secret"]
        list_serializer_class = ParamListSerializer

    def get_value(self, param: Parameter):
        if hasattr(param, "value") and hasattr(param, "is_from_org"):
            if param.is_secret and param.is_from_org:
                return "redacted"
            return param.value


class PythonConfigListSerializer(rfs.ListSerializer):
    plugins = rfs.PrimaryKeyRelatedField(read_only=True)

    def to_representation_single_plugin(self, plugin: PythonConfig, user: User):
        cache_name = (
            f"serializer_{plugin.__class__.__name__}_{plugin.name}_{user.username}"
        )
        cache_hit = cache.get(cache_name)
        if not cache_hit:
            plugin_representation = self.child.to_representation(plugin)
            plugin_representation["secrets"] = {}
            plugin_representation["params"] = {}
            total_parameters = 0
            parameter_required_not_configured = []
            for param in plugin.python_module.parameters.annotate_configured(
                plugin, user
            ).annotate_value_for_user(plugin, user):
                total_parameters += 1
                if param.required and not param.configured:
                    parameter_required_not_configured.append(param.name)
                param_representation = ParameterSerializer(param).data
                param_representation.pop("name")
                key = "secrets" if param.is_secret else "params"

                plugin_representation[key][param.name] = param_representation

            if not parameter_required_not_configured:
                logger.debug(f"Plugin {plugin.name} is configured")
                configured = True
                details = "Ready to use!"
            else:
                logger.debug(f"Plugin {plugin.name} is not configured")
                details = (
                    f"{', '.join(parameter_required_not_configured)} "
                    "secret"
                    f"{'' if len(parameter_required_not_configured) == 1 else 's'}"
                    " not set;"
                    f" ({total_parameters - len(parameter_required_not_configured)} "
                    f"of {total_parameters} satisfied)"
                )
                configured = False
            plugin_representation["disabled"] = not plugin.enabled_for_user(user)
            plugin_representation["verification"] = {
                "configured": configured,
                "details": details,
                "missing_secrets": parameter_required_not_configured,
            }
            logger.info(f"Setting cache {cache_name}")
            cache.set(cache_name, plugin_representation, timeout=60 * 60 * 24 * 7)
            return plugin_representation
        else:
            cache.touch(cache_name, timeout=60 * 60 * 24 * 7)
            return cache_hit

    def to_representation(self, data):
        user = self.context["request"].user
        for plugin in data:
            yield self.to_representation_single_plugin(plugin, user)


class PythonModulSerializerComplete(rfs.ModelSerializer):
    health_check_schedule = CrontabScheduleSerializer()
    update_schedule = CrontabScheduleSerializer()

    class Meta:
        model = PythonModule
        exclude = ["id", "update_task"]


class PythonModuleSerializer(rfs.ModelSerializer):
    class Meta:
        model = PythonModule
        fields = ["module", "base_path"]


class ParameterCompleteSerializer(rfs.ModelSerializer):
    python_module = PythonModuleSerializer(read_only=True)

    class Meta:
        model = Parameter
        exclude = ["id"]


class PluginConfigCompleteSerializer(rfs.ModelSerializer):
    parameter = ParameterCompleteSerializer(read_only=True)
    analyzer_config = rfs.SlugRelatedField(read_only=True, slug_field="name")
    connector_config = rfs.SlugRelatedField(read_only=True, slug_field="name")
    visualizer_config = rfs.SlugRelatedField(read_only=True, slug_field="name")
    ingestor_config = rfs.SlugRelatedField(read_only=True, slug_field="name")
    pivot_config = rfs.SlugRelatedField(read_only=True, slug_field="name")

    class Meta:
        model = PluginConfig
        exclude = ["id"]


class AbstractConfigSerializer(rfs.ModelSerializer):
    ...


class PythonConfigSerializer(AbstractConfigSerializer):
    parameters = ParameterSerializer(write_only=True, many=True)

    class Meta:
        exclude = [
            "python_module",
            "routing_key",
            "soft_time_limit",
            "health_check_status",
            "health_check_task",
        ]
        list_serializer_class = PythonConfigListSerializer

    def to_internal_value(self, data):
        raise NotImplementedError()

    def to_representation(self, instance: PythonConfig):
        result = super().to_representation(instance)
        result["disabled"] = result["disabled"] | instance.health_check_status
        result["config"] = {
            "queue": instance.get_routing_key(),
            "soft_time_limit": instance.soft_time_limit,
        }
        return result


class AbstractConfigSerializerForMigration(AbstractConfigSerializer):
    class Meta:
        exclude = ["id"]


class PythonConfigSerializerForMigration(AbstractConfigSerializerForMigration):
    python_module = PythonModulSerializerComplete(read_only=True)
    parameters = ParameterSerializer(write_only=True, many=True)

    class Meta:
        exclude = AbstractConfigSerializerForMigration.Meta.exclude + [
            "health_check_task"
        ]

    def to_representation(self, instance):
        return super().to_representation(instance)
