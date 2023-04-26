# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import List

from django.db.models import OuterRef, Subquery
from rest_framework import serializers as rfs

from api_app.core.models import AbstractReport, Parameter

logger = logging.getLogger(__name__)


class _ConfigSerializer(rfs.Serializer):
    """
    To validate `config` attr.
    """

    queue = rfs.CharField(required=True)
    soft_time_limit = rfs.IntegerField(required=True)


class ParamListSerializer(rfs.ListSerializer):
    @property
    def data(self):
        # this is to return a dict instead of a list
        return super(rfs.ListSerializer, self).data

    def to_representation(self, data):
        result = super().to_representation(data)
        return {elem.pop("name"): elem for elem in result}


class ParamSerializer(rfs.ModelSerializer):
    class Meta:
        model = Parameter
        fields = [
            "value",
            "name",
            "type",
        ]
        list_serializer_class = ParamListSerializer

    value = rfs.SerializerMethodField(read_only=True)

    def get_value(self, instance: Parameter):
        return instance.get_first_value(self.context["request"].user).value


class AbstractListConfigSerializer(rfs.ListSerializer):

    plugins = rfs.PrimaryKeyRelatedField(read_only=True)

    def to_representation(self, data):
        from api_app.models import PluginConfig

        plugins = self.child.Meta.model.objects.filter(
            pk__in=[plugin.pk for plugin in data]
        )
        user = self.context["request"].user
        enabled_plugins = plugins.filter(disabled=False)
        if user and user.has_membership():
            enabled_plugins = enabled_plugins.exclude(
                disabled_in_organizations=user.membership.organization.pk
            )

        # get the values for that configurations
        configurations = PluginConfig.visible_for_user(user).filter(
            **{f"parameter__{self.child.Meta.model.snake_case_name}__pk__in": plugins}
        )
        # ????
        subquery_owner = Subquery(
            configurations.filter(
                parameter=OuterRef("pk"), owner=user, for_organization=False
            ).values("value")[:1]
        )
        subquery_default = Subquery(
            configurations.filter(parameter=OuterRef("pk"))
            .filter(owner__isnull=True)
            .values("value")[:1]
        )
        if user.has_membership():
            subquery_org = Subquery(
                configurations.filter(parameter=OuterRef("pk"))
                .filter(for_organization=True, owner=user.membership.organization.owner)
                .values("value")[:1]
            )
        else:
            from django.db.models import Value

            subquery_org = Value(False)
        # annotate if the params are configured or not with the subquery
        params = Parameter.objects.filter(
            **{f"{self.child.Meta.model.snake_case_name}__pk__in": plugins}
        ).annotate(
            value_owner=subquery_owner,
            value_default=subquery_default,
            value_organization=subquery_org,
        )

        parsed = {}
        for plugin in plugins:
            parsed[plugin] = {}
        for parameter in params:
            parsed[getattr(parameter, self.child.Meta.model.snake_case_name)][
                parameter
            ] = (
                bool(
                    parameter.value_owner
                    or parameter.value_organization
                    or parameter.value_default
                ),
                parameter.required,
            )
        result = []

        for config in parsed:
            analyzer_representation = self.child.to_representation(config)
            analyzer_representation["params"] = {}
            total_parameter = len(parsed[config].keys())
            parameter_required_not_configured = []
            for param in parsed[config]:
                configured, required = parsed[config][param]
                if required and not configured:
                    parameter_required_not_configured.append(param.name)
                if not param.is_secret:
                    analyzer_representation["params"][param.name] = (
                        param.value_owner
                        or param.value_organization
                        or param.value_default
                    )
            if not parameter_required_not_configured:
                configured = True
                details = "Ready to use!"
            else:
                details = (
                    f"{', '.join(parameter_required_not_configured)} "
                    f"secret{'' if len(parameter_required_not_configured) == 1 else 's'} not set;"
                    f" ({total_parameter - len(parameter_required_not_configured)} "
                    f"of {total_parameter} satisfied)"
                )
                configured = False
            if config in enabled_plugins:
                disabled = False
            else:
                disabled = True
            # analyzer_representation["params"][param.name] = param.value
            analyzer_representation["disabled"] = disabled
            analyzer_representation["verification"] = {
                "configured": configured,
                "details": details,
                "missing_secrets": parameter_required_not_configured,
            }
            result.append(analyzer_representation)
        return result


class AbstractConfigSerializer(rfs.ModelSerializer):

    config = _ConfigSerializer(required=True)
    # params = ParamSerializer(read_only=True, many=True, source="options")
    parameters = ParamSerializer(write_only=True, many=True)

    class Meta:
        exclude = ["disabled_in_organizations"]

    def validate_params(self, params: List[Parameter]):
        return [param for param in params if not param.is_secret]

    def validate_secrets(self, secrets: List[Parameter]):
        return [secret for secret in secrets if secret.is_secret]

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
