from rest_flex_fields import FlexFieldsModelSerializer

from api_app.data_model_manager.models import IETFReport, Signature, DomainDataModel, IPDataModel, FileDataModel


class IETFReportSerializer(FlexFieldsModelSerializer):
    class Meta:
        model = IETFReport
        fields = "__all__"


class SignatureSerializer(FlexFieldsModelSerializer):
    class Meta:
        model = Signature
        fields = "__all__"


class BaseDataModelSerializer(FlexFieldsModelSerializer):
    ...


class DomainDataModelSerializer(BaseDataModelSerializer):
    ietf_report = IETFReportSerializer()
    class Meta:
        model = DomainDataModel
        fields = "__all__"


class IPDataModelSerializer(BaseDataModelSerializer):
    ietf_report = IETFReportSerializer()

    class Meta:
        model = IPDataModel
        fields = "__all__"


class FileDataModelSerializer(BaseDataModelSerializer):
    signatures = SignatureSerializer(many=True)
    class Meta:
        model = FileDataModel
        fields = "__all__"