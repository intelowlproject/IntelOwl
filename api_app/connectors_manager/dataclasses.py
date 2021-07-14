# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import dataclasses

from api_app.core.dataclasses import AbstractConfig


__all__ = ["ConnectorConfig"]


@dataclasses.dataclass
class ConnectorConfig(AbstractConfig):
    pass
