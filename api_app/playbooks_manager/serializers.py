# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from rest_framework import serializers as rfs

from api_app.analyzers_manager.constants import TypeChoices
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import ScanMode
from api_app.connectors_manager.models import ConnectorConfig
from api_app.pivots_manager.models import PivotConfig
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.serializers import TagSerializer


class PlaybookConfigSerializer(rfs.ModelSerializer):
    class Meta:
        model = PlaybookConfig
        exclude = ["disabled_in_organizations"]

    type = rfs.ListField(child=rfs.CharField(read_only=True), read_only=True)
    analyzers = rfs.PrimaryKeyRelatedField(
        many=True,
        queryset=AnalyzerConfig.objects.all(),
        required=True,
        allow_empty=False,
    )
    connectors = rfs.PrimaryKeyRelatedField(
        many=True, queryset=ConnectorConfig.objects.all(), required=True
    )
    visualizers = rfs.PrimaryKeyRelatedField(read_only=True, many=True)

    pivots = rfs.PrimaryKeyRelatedField(
        many=True, queryset=PivotConfig.objects.all(), required=True
    )
    runtime_configuration = rfs.DictField(required=True)

    scan_mode = rfs.ChoiceField(choices=ScanMode.choices, required=True)
    scan_check_time = rfs.DurationField(required=True, allow_null=True)
    tags = TagSerializer(required=False, allow_empty=True, many=True)
    tlp = rfs.CharField(read_only=True)

    def create(self, validated_data):
        types_supported = list(
            set(
                [
                    type_supported
                    for analyzer_config in validated_data["analyzers"]
                    for type_supported in analyzer_config.observable_supported
                ]
            )
        )
        if any((x.type == TypeChoices.FILE.value for x in validated_data["analyzers"])):
            types_supported.append(TypeChoices.FILE)
        validated_data["type"] = types_supported
        return super().create(validated_data)
