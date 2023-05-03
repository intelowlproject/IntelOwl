# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from collections import defaultdict

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


class ParameterCompleteSerializer(rfs.ModelSerializer):
    class Meta:
        model = Parameter
        fields = rfs.ALL_FIELDS


class ParameterSerializer(rfs.ModelSerializer):
    class Meta:
        model = Parameter
        fields = ["name", "type", "description", "required"]
        list_serializer_class = ParamListSerializer


class AbstractListConfigSerializer(rfs.ListSerializer):

    plugins = rfs.PrimaryKeyRelatedField(read_only=True)

    def to_representation(self, data):
        from api_app.models import PluginConfig

        plugins = self.child.Meta.model.objects.filter(
            pk__in=[plugin.pk for plugin in data]
        )
        user = self.context["request"].user
        enabled_plugins = plugins.filter(disabled=False)

        # get the values for that configurations
        configurations = PluginConfig.visible_for_user(user).filter(
            **{f"parameter__{self.child.Meta.model.snake_case_name}__pk__in": plugins}
        )
        # value for owner
        subquery_owner = Subquery(
            configurations.filter(
                parameter=OuterRef("pk"), owner=user, for_organization=False
            ).values("value")[:1]
        )
        # value for default
        subquery_default = Subquery(
            configurations.filter(parameter=OuterRef("pk"))
            .filter(owner__isnull=True)
            .values("value")[:1]
        )
        # value for org
        if user and user.has_membership():
            subquery_org = Subquery(
                configurations.filter(parameter=OuterRef("pk"))
                .filter(for_organization=True, owner=user.membership.organization.owner)
                .values("value")[:1]
            )
            enabled_plugins = enabled_plugins.exclude(
                disabled_in_organizations=user.membership.organization.pk
            )
        else:
            from django.db.models import Value

            subquery_org = Value(False)
        # annotate if the params are configured or not with the subquery
        params = (
            Parameter.objects.filter(
                **{f"{self.child.Meta.model.snake_case_name}__pk__in": plugins}
            )
            .prefetch_related(self.child.Meta.model.snake_case_name)
            .annotate(
                value_owner=subquery_owner,
                value_default=subquery_default,
                value_organization=subquery_org,
            )
        )
        parsed = defaultdict(list)
        # populate the result for every plugin (even the ones without parameters)
        # parsed[plugin]= [parameter1]
        for parameter in params:
            parsed[getattr(parameter, self.child.Meta.model.snake_case_name)].append(
                parameter
            )

        result = []
        # we can finally construct our result
        for plugin in plugins:
            plugin_representation = self.child.to_representation(plugin)
            plugin_representation["params"] = {}
            plugin_representation["secrets"] = {}
            total_parameter = len(parsed[plugin])
            parameter_required_not_configured = []
            for param in parsed[plugin]:
                # the priority order is
                # 1 owner
                # 2 organization
                # 3 default
                value = (
                    param.value_owner or param.value_organization or param.value_default
                )
                if param.required and not bool(value):
                    parameter_required_not_configured.append(param.name)
                param_representation = ParameterSerializer(param).data
                if param.is_secret and value == param.value_organization:
                    value = "redacted"
                param_representation["value"] = value
                param_representation.pop("name")
                if param.is_secret:
                    plugin_representation["secrets"][param.name] = param_representation
                else:
                    plugin_representation["params"][param.name] = param_representation
            if not parameter_required_not_configured:
                configured = True
                details = "Ready to use!"
            else:
                details = (
                    f"{', '.join(parameter_required_not_configured)} "
                    "secret"
                    f"{'' if len(parameter_required_not_configured) == 1 else 's'}"
                    " not set;"
                    f" ({total_parameter - len(parameter_required_not_configured)} "
                    f"of {total_parameter} satisfied)"
                )
                configured = False
            if plugin in enabled_plugins:
                disabled = False
            else:
                disabled = True
            # plugin_representation["params"][param.name] = param.value
            plugin_representation["disabled"] = disabled
            plugin_representation["verification"] = {
                "configured": configured,
                "details": details,
                "missing_secrets": parameter_required_not_configured,
            }
            result.append(plugin_representation)

        return result


class AbstractConfigSerializer(rfs.ModelSerializer):

    config = _ConfigSerializer(required=True)
    parameters = ParameterSerializer(write_only=True, many=True)

    class Meta:
        exclude = ["disabled_in_organizations"]

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
