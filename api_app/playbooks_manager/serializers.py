# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import django.core.exceptions
from rest_framework import serializers as rfs
from rest_framework.exceptions import ValidationError

from api_app.analyzers_manager.constants import TypeChoices
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.pivots_manager.models import PivotConfig
from api_app.playbooks_manager.models import PlaybookConfig


class PlaybookConfigSerializer(rfs.ModelSerializer):

    type = rfs.ListField(child=rfs.CharField(read_only=True), read_only=True)
    analyzers = rfs.PrimaryKeyRelatedField(
        many=True, queryset=AnalyzerConfig.objects.all(), required=True
    )
    connectors = rfs.PrimaryKeyRelatedField(
        many=True, queryset=ConnectorConfig.objects.all(), required=True
    )
    pivots = rfs.PrimaryKeyRelatedField(
        many=True, queryset=PivotConfig.objects.all(), required=True
    )
    runtime_configuration = rfs.DictField(required=True)

    class Meta:
        model = PlaybookConfig
        fields = rfs.ALL_FIELDS

    def validate_analyzers(self, analyzers):
        if not analyzers:
            raise ValidationError("You must have at least one analyzer")
        return analyzers

    @staticmethod
    def create(validated_data):

        types_supported = list(
            set(
                [
                    type_supported
                    for analyzer_config in validated_data.get("analyzers", [])
                    for type_supported in analyzer_config.observable_supported
                ]
            )
        )
        if any((x.type == TypeChoices.FILE.value for x in validated_data["analyzers"])):
            types_supported.append(TypeChoices.FILE)
        pc = PlaybookConfig(
            name=validated_data["name"],
            description=validated_data["description"],
            type=types_supported,
            runtime_configuration=validated_data["runtime_configuration"],
        )
        try:
            pc.full_clean()
        except django.core.exceptions.ValidationError as e:
            raise ValidationError({"detail": e})
        pc.save()
        pc.analyzers.set(validated_data["analyzers"])
        pc.connectors.set(validated_data["connectors"])
        pc.pivots.set(validated_data["connectors"])
        return pc
