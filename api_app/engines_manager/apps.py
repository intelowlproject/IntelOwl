# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.apps import AppConfig


class EnginesManagerConfig(AppConfig):
    name = "api_app.engines_manager"

    @staticmethod
    def ready(**kwargs) -> None:
        from . import signals  # noqa
