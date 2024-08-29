from django.contrib import admin

from data_model.models import BaseDataModel, DomainDataModel, FileDataModel, IPDataModel


@admin.register(BaseDataModel)
class BaseDataModelAdminView(admin.ModelAdmin):
    list_display = (
        "evaluation",
        "related_urls",
        "related_threats",
        "family",
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
        "tags",
        "compromised_hosts",
        "signatures",
        "yara_rules",
        "comments",
        "file_information",
        "stats",
    )
