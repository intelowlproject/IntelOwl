# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.apps import AppConfig
from django.conf import settings

from intel_owl.settings.cache import set_permissions


class AnalyzersManagerConfig(AppConfig):
    name = "api_app.analyzers_manager"

    def ready(self):
        set_permissions(settings.DEFAULT_CACHE)
