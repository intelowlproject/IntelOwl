from rest_flex_fields import FlexFieldsModelSerializer
from rest_framework import serializers
from rest_framework.serializers import SlugRelatedField

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


class BaseDataModelSerializer(FlexFieldsModelSerializer):
    analyzers_report = SlugRelatedField(slug_field="pk", read_only=True, many=True)

    class Meta:
        fields = "__all__"


class DomainDataModelSerializer(BaseDataModelSerializer):
    ietf_report = IETFReportSerializer(many=True, read_only=True)

    class Meta:
        model = DomainDataModel
        fields = "__all__"


class IPDataModelSerializer(BaseDataModelSerializer):
    ietf_report = IETFReportSerializer(many=True, read_only=True)
    analyzers_report = SlugRelatedField(slug_field="pk", read_only=True, many=True)

    class Meta:
        model = IPDataModel
        fields = "__all__"


class FileDataModelSerializer(BaseDataModelSerializer):
    signatures = SignatureSerializer(many=True)
    analyzers_report = SlugRelatedField(slug_field="pk", read_only=True, many=True)

    class Meta:
        model = FileDataModel
        fields = "__all__"


class DataModelRelatedField(serializers.RelatedField):
    def to_representation(self, value):
        if isinstance(value, DomainDataModel):
            internal_serializer = DomainDataModelSerializer(value, omit=self.context.get("omit", []))
        elif isinstance(value, IPDataModel):
            internal_serializer = IPDataModelSerializer(value, omit=self.context.get("omit", []))
        elif isinstance(value, FileDataModel):
            internal_serializer = FileDataModelSerializer(value, omit=self.context.get("omit", []))
        else:
            raise RuntimeError("Unexpected type of of data_model")
        return internal_serializer.data
