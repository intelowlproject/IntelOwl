from django.contrib import admin

from api_app.models import PluginConfig


class PluginConfigInline(admin.TabularInline):
    model = PluginConfig
    extra = 1
    max_num = 1
    fields = ["value"]
