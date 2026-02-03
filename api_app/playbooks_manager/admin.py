# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin, messages
from django.core.exceptions import ValidationError
from django.http import HttpResponse, HttpResponseRedirect

from api_app.admin import AbstractConfigAdminView, ModelWithOwnershipAdminView
from api_app.choices import ScanMode
from api_app.playbooks_manager.models import PlaybookConfig


@admin.register(PlaybookConfig)
class PlaybookConfigAdminView(AbstractConfigAdminView, ModelWithOwnershipAdminView):
    list_display = (
        "name",
        "type",
        "disabled",
        "get_analyzers",
        "get_connectors",
        "get_pivots",
        "get_visualizers",
        "scan_mode",
        "starting",
    ) + ModelWithOwnershipAdminView.list_display
    list_filter = (
        AbstractConfigAdminView.list_filter + ("starting",) + ModelWithOwnershipAdminView.list_filter
    )

    @staticmethod
    def _get_plugins(qs):
        return [elem.name for elem in qs]

    @admin.display(description="Analyzers")
    def get_analyzers(self, obj: PlaybookConfig):
        return self._get_plugins(obj.analyzers.all())

    @admin.display(description="Connectors")
    def get_connectors(self, obj: PlaybookConfig):
        return self._get_plugins(obj.connectors.all())

    @admin.display(description="Pivots")
    def get_pivots(self, obj: PlaybookConfig):
        return self._get_plugins(obj.pivots.all())

    @admin.display(description="Visualizers")
    def get_visualizers(self, obj: PlaybookConfig):
        return self._get_plugins(obj.visualizers.all())

    @staticmethod
    def scan_mode(obj: PlaybookConfig) -> str:
        return ScanMode(obj.scan_mode).name

    def change_view(self, request, *args, **kwargs) -> HttpResponse:
        try:
            return super().change_view(request, *args, **kwargs)
        except ValidationError as e:
            self.message_user(request, str(e), level=messages.ERROR)
            return HttpResponseRedirect(request.path)
