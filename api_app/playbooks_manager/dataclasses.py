# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import dataclasses
import typing

from .serializers import PlaybookConfigSerializer

__all__ = ["PlaybookConfig"]

# Try to see if your changes in serializers helps with the changeshere (make them)

@dataclasses.dataclass
class PlaybookConfig:
    name: str
    description: str
    supports: typing.List[str]
    disabled: bool
    analyzers: typing.Dict[str, typing.Any]
    connectors: typing.Dict[str, typing.Any]

    serializer_class = PlaybookConfigSerializer

    @property
    def is_ready_to_use(self) -> bool:
        return not self.disabled
    
    @classmethod
    def from_dict(cls, data: dict) -> "PlaybookConfig":
        [data.pop(key) for key in ["config", "verification", "secrets", "params", "python_module"]]
        return cls(**data)

    # orm methods
    @classmethod
    def get(cls, playbook_name: str) -> typing.Optional["PlaybookConfig"]:
        """
        Returns config dataclass by playbook_name if found, else None
        """
        all_configs = cls.serializer_class.read_and_verify_config()
        config_dict = all_configs.get(playbook_name, None)
        if config_dict is None:
            return None  # not found
        return cls.from_dict(config_dict)

    @classmethod
    def all(cls) -> typing.Dict[str, "PlaybookConfig"]:
        return {
            name: cls.from_dict(attrs)
            for name, attrs in cls.serializer_class.read_and_verify_config().items()
        }

    @classmethod
    def filter(cls, names: typing.List[str]) -> typing.Dict[str, "PlaybookConfig"]:
        all_playbook_configs = cls.all()
        return {name: cc for name, cc in all_playbook_configs.items() if name in names}
