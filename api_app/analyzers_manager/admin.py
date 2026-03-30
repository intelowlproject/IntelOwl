# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from django.contrib import admin

from api_app.admin import AbstractReportAdminView, PythonConfigAdminView
from api_app.analyzers_manager.models import (
    AnalyzerConfig,
    AnalyzerReport,
    PhishingArmyDomain,
    Ja4DBEntry,
    TorDanMeUKNode,
    TorExitNode,
    TweetFeedItem,
    SpamhausDropItem,
    StratosphereIPEntry,
    FireholIPEntry,
)


# flake8: noqa
@admin.register(AnalyzerReport)
class AnalyzerReportAdminView(AbstractReportAdminView): ...


@admin.register(AnalyzerConfig)
class AnalyzerConfigAdminView(PythonConfigAdminView):
    list_display = PythonConfigAdminView.list_display + (
        "type",
        "docker_based",
        "maximum_tlp",
    )
    list_filter = ["type", "maximum_tlp"] + PythonConfigAdminView.list_filter
    exclude = ["update_task"]


@admin.register(TorExitNode)
class TorExitNodeAdmin(admin.ModelAdmin):
    list_display = ["ip", "updated_at"]


@admin.register(TorDanMeUKNode)
class TorDanMeUKNodeAdmin(admin.ModelAdmin):
    list_display = ["ip", "updated_at"]


@admin.register(PhishingArmyDomain)
class PhishingArmyDomainAdmin(admin.ModelAdmin):
    list_display = ["domain", "updated_at"]


@admin.register(TweetFeedItem)
class TweetFeedItemAdmin(admin.ModelAdmin):
    list_display = ["value", "updated_at"]


@admin.register(SpamhausDropItem)
class SpamhausDropItemAdmin(admin.ModelAdmin):
    list_display = ["data_type", "value", "network_address", "updated_at"]
    list_filter = ["data_type"]
    search_fields = ["value", "network_address"]


@admin.register(StratosphereIPEntry)
class StratosphereIPEntryAdmin(admin.ModelAdmin):
    list_display = ["ip", "list_type", "rating", "updated_at"]
    list_filter = ["list_type"]
    search_fields = ["ip"]


@admin.register(FireholIPEntry)
class FireholIPEntryAdmin(admin.ModelAdmin):
    list_display = ["ip_or_subnet", "list_name", "network_address", "updated_at"]
    list_filter = ["list_name"]
    search_fields = ["ip_or_subnet", "network_address"]


@admin.register(Ja4DBEntry)
class Ja4DBEntryAdmin(admin.ModelAdmin):
    list_display = ["fingerprint_type", "fingerprint_value", "updated_at"]
    list_filter = ["fingerprint_type"]
    search_fields = ["fingerprint_value"]
