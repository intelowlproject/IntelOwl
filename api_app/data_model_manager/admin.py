from django.contrib import admin

from api_app.admin import CustomAdminView
from api_app.data_model_manager.models import (
    DomainDataModel,
    FileDataModel,
    IPDataModel,
)


class BaseDataModelAdminView(CustomAdminView):
    list_display = (
        "pk",
        "evaluation",
        "external_references",
        "related_threats",
        "tags",
        "malware_family",
        "additional_info",
    )


@admin.register(DomainDataModel)
class DomainDataModelAdminView(BaseDataModelAdminView):
    list_display = BaseDataModelAdminView.list_display + ("rank", "get_ietf_report")

    @admin.display(description="IETF Reports")
    def get_ietf_report(self, instance: DomainDataModel):
        return list(map(str, instance.ietf_report.all()))


@admin.register(IPDataModel)
class IPDataModelAdminView(BaseDataModelAdminView):
    list_display = BaseDataModelAdminView.list_display + (
        "get_ietf_report",
        "asn",
        "asn_rank",
        "certificates",
        "org_name",
        "country_code",
        "registered_country_code",
        "isp",
    )

    @admin.display(description="IETF Reports")
    def get_ietf_report(self, instance: IPDataModel):
        return list(map(str, instance.ietf_report.all()))


@admin.register(FileDataModel)
class FileDataModelAdminView(BaseDataModelAdminView):
    list_display = BaseDataModelAdminView.list_display + (
        "get_signatures",
        "comments",
        "file_information",
        "stats",
    )

    @admin.display(description="Signatures")
    def get_signatures(self, instance: FileDataModel):
        return list(map(str, instance.signatures.all()))
