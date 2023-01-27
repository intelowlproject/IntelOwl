# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from django.conf import settings
from django.utils.module_loading import import_string
from rest_framework import serializers as rfs

from api_app.core.serializers import AbstractConfigSerializer
from api_app.models import PluginConfig

from .constants import HashChoices, ObservableTypes, TypeChoices
from .models import AnalyzerReport


class AnalyzerReportSerializer(rfs.ModelSerializer):
    """
    AnalyzerReport model's serializer.
    """

    type = rfs.CharField(default="analyzer")

    class Meta:
        model = AnalyzerReport
        fields = (
            "name",
            "status",
            "report",
            "errors",
            "process_time",
            "start_time",
            "end_time",
            "runtime_configuration",
            "type",
            "parent_playbook",
        )


class AnalyzerConfigSerializer(AbstractConfigSerializer):
    """
    Serializer for `analyzer_config.json`.
    """

    CONFIG_FILE_NAME = "analyzer_config.json"

    TypeChoices = TypeChoices
    HashChoices = HashChoices
    ObservableTypes = ObservableTypes

    # Required fields
    type = rfs.ChoiceField(required=True, choices=TypeChoices.values)
    external_service = rfs.BooleanField(required=True)
    # Optional Fields
    leaks_info = rfs.BooleanField(required=False, default=False)
    docker_based = rfs.BooleanField(required=False, default=False)
    run_hash = rfs.BooleanField(required=False, default=False)
    run_hash_type = rfs.ChoiceField(required=False, choices=HashChoices.values)
    supported_filetypes = rfs.ListField(required=False, default=[])
    not_supported_filetypes = rfs.ListField(required=False, default=[])
    observable_supported = rfs.ListField(
        child=rfs.ChoiceField(choices=ObservableTypes.values),
        required=False,
        default=[],
    )

    def _get_type(self):
        return PluginConfig.PluginType.ANALYZER

    def validate_python_module(self, python_module: str) -> str:
        if self.initial_data["type"] == self.TypeChoices.OBSERVABLE or (
            self.initial_data["type"] == self.TypeChoices.FILE
            and self.initial_data.get("run_hash", False)
        ):
            clspath = f"{settings.BASE_ANALYZER_OBSERVABLE_PYTHON_PATH}.{python_module}"
        else:
            clspath = f"{settings.BASE_ANALYZER_FILE_PYTHON_PATH}.{python_module}"

        try:
            import_string(clspath)
        except ImportError as exc:
            raise rfs.ValidationError(
                f"`python_module` incorrect, {clspath} couldn't be imported"
            ) from exc

        return python_module
