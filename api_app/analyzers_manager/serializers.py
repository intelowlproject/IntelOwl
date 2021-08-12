# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.utils.module_loading import import_string
from rest_framework import serializers as rfs

from api_app.core.serializers import AbstractConfigSerializer
from .models import AnalyzerReport
from .constants import TypeChoices, HashChoices, ObservableTypes


class AnalyzerReportSerializer(rfs.ModelSerializer):
    """
    AnalyzerReport model's serializer.
    """

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

    def validate_python_module(self, python_module: str):
        if self.initial_data["type"] == self.TypeChoices.OBSERVABLE or (
            self.initial_data["type"] == self.TypeChoices.FILE
            and self.initial_data.get("run_hash", False)
        ):
            clspath = f"api_app.analyzers_manager.observable_analyzers.{python_module}"
        else:
            clspath = f"api_app.analyzers_manager.file_analyzers.{python_module}"

        try:
            import_string(clspath)
        except ImportError:
            raise rfs.ValidationError(
                f"`python_module` incorrect, {clspath} couldn't be imported"
            )

        return python_module
