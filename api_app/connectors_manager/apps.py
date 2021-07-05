# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.apps import AppConfig


class ConnectorsManagerConfig(AppConfig):
    name = "api_app.connectors_manager"

    def ready(self):
        from .serializers import ConnectorConfigSerializer  # to avoid import issue

        # we "greedy cache" the config at start of application
        # because it is an expensive operation
        ConnectorConfigSerializer.read_and_verify_config()
