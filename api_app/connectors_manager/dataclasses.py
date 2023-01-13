# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import dataclasses
import logging
import typing

from api_app.core.dataclasses import AbstractConfig

from .serializers import ConnectorConfigSerializer

__all__ = ["ConnectorConfig"]

from ..models import PluginConfig

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class ConnectorConfig(AbstractConfig):
    maximum_tlp: str

    @classmethod
    def _get_serializer_class(cls) -> typing.Type[ConnectorConfigSerializer]:
        return ConnectorConfigSerializer

    def _get_type(self) -> str:
        return PluginConfig.PluginType.CONNECTOR

    def get_full_import_path(self) -> str:
        return f"api_app.connectors_manager.connectors.{self.python_module}"

    @classmethod
    def _get_task(cls) -> typing.Callable:
        from intel_owl import tasks

        return tasks.run_connector
