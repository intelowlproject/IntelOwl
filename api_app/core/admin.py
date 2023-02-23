from django.contrib import admin
from django.db.models import JSONField
from prettyjson import PrettyJSONWidget


class AbstractReportAdminView(admin.ModelAdmin):
    list_display = (
        "id",
        "name",
        "job",
        "status",
        "start_time",
        "end_time",
    )
    list_display_links = ("id",)
    search_fields = ("name",)

    def has_add_permission(self, request):
        return False


class AbstractConfigAdminView(admin.ModelAdmin):
    list_display = (
        "name",
        "python_module",
        "description",
        "disabled",
    )
    # allow to clone the object
    save_as = True
    # json
    formfield_overrides = {
        JSONField: {"widget": PrettyJSONWidget(attrs={"initial": "parsed"})}
    }
