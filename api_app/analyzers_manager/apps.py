# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.apps import AppConfig


class AnalyzersManagerConfig(AppConfig):
    name = "api_app.analyzers_manager"

    def ready(self):
        import os
        from .serializers import AnalyzerConfigSerializer  # to avoid import issue

        if os.environ.get("ANALYZER_CONFIG_INIT", None) is None:
            os.environ["ANALYZER_CONFIG_INIT"] = str(True)
            AnalyzerConfigSerializer.read_and_verify_config(_refresh=True)
