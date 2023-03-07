# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin

from .models import Job, PluginConfig, Tag


@admin.register(Job)
class JobAdminView(admin.ModelAdmin):
    list_display = (
        "id",
        "status",
        "user",
        "observable_name",
        "observable_classification",
        "file_name",
        "file_mimetype",
        "received_request_time",
        "analyzers_executed",
        "connectors_executed",
        "visualizers_executed",
    )
    list_display_link = (
        "id",
        "user",
        "status",
    )
    search_fields = (
        "md5",
        "observable_name",
        "file_name",
    )
    list_filter = (
        "status",
        "user",
    )

    def analyzers_executed(self, instance: Job):
        return [analyzer.name for analyzer in instance.analyzers_to_execute.all()]

    def connectors_executed(self, instance: Job):
        return [connector.name for connector in instance.connectors_to_execute.all()]

    def visualizers_executed(self, instance: Job):
        return [visualizer.name for visualizer in instance.visualizers_to_execute.all()]


@admin.register(Tag)
class TagAdminView(admin.ModelAdmin):
    list_display = ("id", "label", "color")
    search_fields = ("label", "color")


@admin.register(PluginConfig)
class PluginCredentialAdminView(admin.ModelAdmin):
    list_display = (
        "id",
        "type",
        "attribute",
        "plugin_name",
        "config_type",
        "organization",
        "owner",
    )
    search_fields = ("attribute", "plugin_name", "organization", "owner")
    list_filter = ("config_type", "type", "plugin_name", "organization", "owner")
