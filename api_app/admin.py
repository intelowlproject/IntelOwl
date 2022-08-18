# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin

from .models import Job, Tag


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


@admin.register(Tag)
class TagAdminView(admin.ModelAdmin):
    list_display = ("id", "label", "color")
    search_fields = ("label", "color")
