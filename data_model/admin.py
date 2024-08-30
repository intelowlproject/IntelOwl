from django.contrib import admin

from data_model.models import BaseDataModel, DomainDataModel, FileDataModel, IPDataModel


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
        "signatures",
        "comments",
        "file_information",
        "stats",
    )
