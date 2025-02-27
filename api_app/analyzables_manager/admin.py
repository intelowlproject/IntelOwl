from django.contrib import admin

from api_app.analyzables_manager.models import Analyzable


@admin.register(Analyzable)
class AnalyzableAdmin(admin.ModelAdmin):
    list_display = ["pk", "name", "sha1", "sha256", "md5"]
    search_fields = ["name", "sha1", "sha256", "md5"]
    ordering = ["name"]
    list_filter = ["discovery_date"]
