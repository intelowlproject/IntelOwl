# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.apps import AppConfig


class ConnectorsManagerConfig(AppConfig):
    """Configuration class for the connectors_manager Django app."""
    name = "api_app.connectors_manager"

    @staticmethod
    def ready() -> None:
        from . import signals  # noqa: F401
