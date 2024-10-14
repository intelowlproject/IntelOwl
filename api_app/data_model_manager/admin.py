from django.contrib import admin

from api_app.data_model_manager.models import (
    BaseDataModel,
    DomainDataModel,
    FileDataModel,
    IPDataModel,
)


@admin.register(BaseDataModel)
class BaseDataModelAdminView(admin.ModelAdmin):
    list_display = (
        "evaluation",
        "external_references",
        "related_threats",
        "tags",
        "malware_family",
        "additional_info",
    )


@admin.register(DomainDataModel)
class DomainDataModelAdminView(BaseDataModelAdminView):
    list_display = BaseDataModelAdminView.list_display + (
        "ietf_report",
        "rank",
    )


@admin.register(IPDataModel)
class IPDataModelAdminView(BaseDataModelAdminView):
    list_display = BaseDataModelAdminView.list_display + (
        "ietf_report",
        "asn",
        "asn_rank",
        "certificates",
        "org_name",
        "country",
        "country_code",
        "registered_country",
        "registered_country_code",
        "isp",
    )


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