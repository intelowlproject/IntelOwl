# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.apps import AppConfig


class ConnectorsManagerConfig(AppConfig):
    name = "api_app.connectors_manager"

    def ready(self):
        import os
        from .serializers import ConnectorConfigSerializer  # to avoid import issue

        if os.environ.get("CONNECTOR_CONFIG_INIT", None) is None:
            os.environ["CONNECTOR_CONFIG_INIT"] = str(True)
            ConnectorConfigSerializer.read_and_verify_config(_refresh=True)
