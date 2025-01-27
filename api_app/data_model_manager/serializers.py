from rest_flex_fields import FlexFieldsModelSerializer
from rest_framework.relations import SlugRelatedField

from api_app.data_model_manager.models import (
    DomainDataModel,
    FileDataModel,
    IETFReport,
    IPDataModel,
    Signature,
)


class IETFReportSerializer(FlexFieldsModelSerializer):
    class Meta:
        model = IETFReport
        exclude = ["id"]

    def create(self, validated_data):
        instance, _ = self.Meta.model.objects.get_or_create(**validated_data)
        return instance


class SignatureSerializer(FlexFieldsModelSerializer):
    class Meta:
        model = Signature
        exclude = ["id"]

    def create(self, validated_data):
        instance, _ = self.Meta.model.objects.get_or_create(**validated_data)
        return instance


class DomainDataModelSerializer(FlexFieldsModelSerializer):
    ietf_report = IETFReportSerializer(many=True)
    analyzers_report = SlugRelatedField(slug_field="pk", read_only=True, many=True)

    class Meta:
        model = DomainDataModel
        fields = "__all__"


class IPDataModelSerializer(FlexFieldsModelSerializer):
    ietf_report = IETFReportSerializer(many=True)
    analyzers_report = SlugRelatedField(slug_field="pk", read_only=True, many=True)

    class Meta:
        model = IPDataModel
        fields = "__all__"


class FileDataModelSerializer(FlexFieldsModelSerializer):
    signatures = SignatureSerializer(many=True)
    analyzers_report = SlugRelatedField(slug_field="pk", read_only=True, many=True)

    class Meta:
        model = FileDataModel
        fields = "__all__"
