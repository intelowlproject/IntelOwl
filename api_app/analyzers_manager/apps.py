# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.apps import AppConfig


class AnalyzersManagerConfig(AppConfig):
    name = "api_app.analyzers_manager"

    @staticmethod
    def ready() -> None:
        from . import signals  # noqa
