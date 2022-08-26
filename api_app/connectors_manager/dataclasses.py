# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import dataclasses
import typing

from api_app.core.dataclasses import AbstractConfig

from .serializers import ConnectorConfigSerializer

__all__ = ["ConnectorConfig"]

from ..models import PluginConfig


@dataclasses.dataclass
class ConnectorConfig(AbstractConfig):
    maximum_tlp: str

    serializer_class = ConnectorConfigSerializer

    def _get_type(self) -> str:
        return PluginConfig.PluginType.ANALYZER

    def get_full_import_path(self) -> str:
        return f"api_app.connectors_manager.connectors.{self.python_module}"

    @classmethod
    def from_dict(cls, data: dict) -> "ConnectorConfig":
        return cls(**data)

    # orm methods

    @classmethod
    def get(cls, connector_name: str) -> typing.Optional["ConnectorConfig"]:
        """
        Returns config dataclass by connector_name if found, else None
        """
        all_configs = cls.serializer_class.read_and_verify_config()
        config_dict = all_configs.get(connector_name, None)
        if config_dict is None:
            return None  # not found
        return cls.from_dict(config_dict)

    @classmethod
    def all(cls) -> typing.Dict[str, "ConnectorConfig"]:
        return {
            name: cls.from_dict(attrs)
            for name, attrs in cls.serializer_class.read_and_verify_config().items()
        }

    @classmethod
    def filter(cls, names: typing.List[str]) -> typing.Dict[str, "ConnectorConfig"]:
        all_connector_configs = cls.all()
        return {name: cc for name, cc in all_connector_configs.items() if name in names}
