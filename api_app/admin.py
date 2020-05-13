from django.contrib import admin
from .models import Job, Tag


class JobAdminView(admin.ModelAdmin):
    list_display = (
        "id",
        "source",
        "observable_name",
        "status",
        "observable_classification",
        "file_mimetype",
        "received_request_time",
    )
    list_display_link = ("id", "status")
    search_fields = ("source", "md5", "observable_name")


class TagAdminView(admin.ModelAdmin):
    list_display = ("id", "label", "color")
    search_fields = ("label", "color")


admin.site.register(Job, JobAdminView)
admin.site.register(Tag, TagAdminView)
