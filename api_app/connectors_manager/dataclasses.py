# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import dataclasses

from api_app.core.dataclasses import AbstractConfig


__all__ = ["ConnectorConfig"]


@dataclasses.dataclass
class ConnectorConfig(AbstractConfig):
    def get_full_import_path(self) -> str:
        return f"api_app.connectors_manager.connectors.{self.python_module}"
