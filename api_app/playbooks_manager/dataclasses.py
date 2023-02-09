# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import dataclasses
import inspect
import typing

from .serializers import PlaybookConfigSerializer

__all__ = ["PlaybookConfig"]

# Try to see if your changes in serializers helps with the changeshere (make them)


@dataclasses.dataclass(frozen=True)
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
    def filter_unwhitelisted_keys(cls, data: dict) -> typing.Dict:
        keys = data.keys()

        signature = inspect.signature(PlaybookConfig.__init__)
        whitelist = list(signature.parameters)[1:]

        cleaned_data = {key: data[key] for key in keys if key in whitelist}

        return cleaned_data

    @classmethod
    def from_dict(cls, data: dict) -> "PlaybookConfig":
        cleaned_data = cls.filter_unwhitelisted_keys(data=data)
        return cls(**cleaned_data)

    # orm methods
    @classmethod
    def get(cls, playbook_name: str) -> typing.Optional["PlaybookConfig"]:
        """
        Returns config dataclass by playbook_name if found, else None
        """
        all_configs = cls.serializer_class.output_with_cached_playbooks()
        config_dict = all_configs.get(playbook_name, None)
        if config_dict is None:
            return None  # not found
        return cls.from_dict(config_dict)

    @classmethod
    def all(cls) -> typing.Dict[str, "PlaybookConfig"]:
        return {
            name: cls.from_dict(attrs)
            for name, attrs in (
                cls.serializer_class.output_with_cached_playbooks().items()
            )
        }

    @classmethod
    def filter(cls, names: typing.List[str]) -> typing.Dict[str, "PlaybookConfig"]:
        all_playbook_configs = cls.all()
        return {name: cc for name, cc in all_playbook_configs.items() if name in names}
