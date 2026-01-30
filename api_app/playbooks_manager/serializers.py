# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from rest_framework import serializers as rfs

from api_app.analyzers_manager.constants import TypeChoices
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import ScanMode
from api_app.connectors_manager.models import ConnectorConfig
from api_app.helpers import gen_random_colorhex
from api_app.models import Tag
from api_app.pivots_manager.models import PivotConfig
from api_app.playbooks_manager.fields import DayDurationField
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.serializers import ModelWithOwnershipSerializer
from api_app.serializers.job import TagSerializer
from api_app.serializers.plugin import AbstractConfigSerializerForMigration
from api_app.visualizers_manager.models import VisualizerConfig


class PlaybookConfigSerializerForMigration(AbstractConfigSerializerForMigration):
    analyzers = rfs.SlugRelatedField(slug_field="name", many=True, read_only=True)
    connectors = rfs.SlugRelatedField(slug_field="name", many=True, read_only=True)
    pivots = rfs.SlugRelatedField(slug_field="name", many=True, read_only=True)

    class Meta:
        model = PlaybookConfig
        exclude = AbstractConfigSerializerForMigration.Meta.exclude


class PlaybookConfigSerializer(ModelWithOwnershipSerializer, rfs.ModelSerializer):
    class Meta:
        model = PlaybookConfig
        fields = rfs.ALL_FIELDS

    type = rfs.ListField(child=rfs.CharField(), required=False)
    analyzers = rfs.SlugRelatedField(
        many=True,
        queryset=AnalyzerConfig.objects.all(),
        required=True,
        allow_empty=False,
        slug_field="name",
    )
    connectors = rfs.SlugRelatedField(
        many=True,
        queryset=ConnectorConfig.objects.all(),
        required=True,
        slug_field="name",
    )
    pivots = rfs.SlugRelatedField(
        many=True, queryset=PivotConfig.objects.all(), required=True, slug_field="name"
    )
    visualizers = rfs.SlugRelatedField(
        many=True,
        queryset=VisualizerConfig.objects.all(),
        required=False,
        slug_field="name",
    )

    runtime_configuration = rfs.DictField(required=True)

    scan_mode = rfs.ChoiceField(choices=ScanMode.choices, required=True)
    scan_check_time = DayDurationField(required=True, allow_null=True)
    tags = TagSerializer(required=False, allow_empty=True, many=True, read_only=True)
    tlp = rfs.CharField(read_only=True)
    weight = rfs.IntegerField(read_only=True, required=False, allow_null=True)
    is_editable = rfs.SerializerMethodField()
    tags_labels = rfs.ListField(
        child=rfs.CharField(required=True),
        default=list,
        required=False,
        write_only=True,
    )

    def get_is_editable(self, instance: PlaybookConfig):
        # if the playbook is not a default one
        if instance.owner:
            # it is editable/deletable by the owner of the playbook
            # or by an admin of the same organization
            if instance.owner == self.context["request"].user or (
                self.context["request"].user.membership.is_admin
                and self.context["request"].user.membership.organization == instance.organization
            ):
                return True
        return False

    @staticmethod
    def validate_tags_labels(tags_labels):
        for label in tags_labels:
            yield Tag.objects.get_or_create(label=label, defaults={"color": gen_random_colorhex()})[0]

    def validate(self, attrs):
        attrs = super().validate(attrs)
        if attrs.get("tags_labels"):
            attrs["tags"] = attrs.pop("tags_labels", [])
        return attrs

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
