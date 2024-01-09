# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from rest_framework import serializers as rfs

from api_app.analyzers_manager.constants import TypeChoices
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import ScanMode
from api_app.connectors_manager.models import ConnectorConfig
from api_app.pivots_manager.models import PivotConfig
from api_app.playbooks_manager.fields import DayDurationField
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.serializers import ModelWithOwnershipSerializer, TagSerializer


class PlaybookConfigSerializer(ModelWithOwnershipSerializer, rfs.ModelSerializer):
    class Meta:
        model = PlaybookConfig
        fields = rfs.ALL_FIELDS

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
    pivots = rfs.SlugRelatedField(
        many=True, queryset=PivotConfig.objects.all(), required=True, slug_field="name"
    )
    visualizers = rfs.PrimaryKeyRelatedField(read_only=True, many=True)

    runtime_configuration = rfs.DictField(required=True)

    scan_mode = rfs.ChoiceField(choices=ScanMode.choices, required=True)
    scan_check_time = DayDurationField(required=True, allow_null=True)
    tags = TagSerializer(required=False, allow_empty=True, many=True)
    tlp = rfs.CharField(read_only=True)
    weight = rfs.IntegerField(read_only=True, required=False, allow_null=True)
    is_deletable = rfs.SerializerMethodField()

    def get_is_deletable(self, instance: PlaybookConfig):
        # if the playbook is not a default one
        if instance.owner:
            # it is deletable by the owner of the playbook
            # or by an admin of the same organization
            if instance.owner == self.context["request"].user or (
                self.context["request"].user.membership.is_admin
                and self.context["request"].user.membership.organization
                == instance.organization
            ):
                return True
        return False

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
