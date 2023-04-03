# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin

from api_app.core.admin import JsonViewerAdminView
from api_app.playbooks_manager.models import PlaybookConfig


@admin.register(PlaybookConfig)
class PluginConfigAdminView(JsonViewerAdminView):
    list_display = (
        "name",
        "type",
        "description",
        "disabled",
        "get_analyzers",
        "get_connectors",
        "runtime_configuration",
    )
    # allow to clone the object
    save_as = True

    def _get_plugins(self, qs):  # noqa
        return [elem.name for elem in qs]

    def get_analyzers(self, obj: PlaybookConfig):
        return self._get_plugins(obj.analyzers.all())

    def get_connectors(self, obj: PlaybookConfig):
        return self._get_plugins(obj.connectors.all())
