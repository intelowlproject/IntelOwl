# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import dataclasses
import typing

from api_app.core.dataclasses import AbstractConfig
from .serializers import ConnectorConfigSerializer


__all__ = ["ConnectorConfig"]


@dataclasses.dataclass
class ConnectorConfig(AbstractConfig):

    serializer_class = ConnectorConfigSerializer

    def get_full_import_path(self) -> str:
        return f"api_app.connectors_manager.connectors.{self.python_module}"

    @classmethod
    def get(cls, connector_name: str) -> typing.Optional["ConnectorConfig"]:
        """
        Returns config dataclass by connector_name if found, else None
        """
        return super().get(connector_name)
