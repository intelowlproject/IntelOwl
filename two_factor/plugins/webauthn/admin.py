from django.contrib.admin import ModelAdmin, register

from .models import WebauthnDevice


@register(WebauthnDevice)
class WebauthnDeviceAdmin(ModelAdmin):
    list_display = ["user", "name", "created_at", "last_used_at", "confirmed"]
    raw_id_fields = ["user"]
