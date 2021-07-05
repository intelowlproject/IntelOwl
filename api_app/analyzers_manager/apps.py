# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.apps import AppConfig


class AnalyzersManagerConfig(AppConfig):
    name = "api_app.analyzers_manager"

    def ready(self):
        from .serializers import AnalyzerConfigSerializer  # to avoid import issue

        # we "greedy cache" the config at start of application
        # because it is an expensive operation
        AnalyzerConfigSerializer.read_and_verify_config()
