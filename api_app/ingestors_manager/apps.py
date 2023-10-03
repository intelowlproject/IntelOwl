# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.apps import AppConfig


class IngestorsManagerConfig(AppConfig):
    name = "api_app.ingestors_manager"

    @staticmethod
    def ready() -> None:
        from . import signals  # noqa
