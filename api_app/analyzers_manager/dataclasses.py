# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import typing
import dataclasses

from api_app.core.dataclasses import AbstractConfig
from .constants import TypeChoices, HashChoices, ObservableTypes
from .serializers import AnalyzerConfigSerializer

__all__ = ["AnalyzerConfig"]


@dataclasses.dataclass
class AnalyzerConfig(AbstractConfig):
    # Required fields
    type: typing.Literal[TypeChoices.values]
    supported_filetypes: typing.List[str]
    not_supported_filetypes: typing.List[str]
    observable_supported: typing.List[typing.Literal[ObservableTypes.values]]
    # Optional Fields
    external_service: bool = False
    leaks_info: bool = False
    docker_based: bool = False
    run_hash: bool = False
    run_hash_type: typing.Literal[HashChoices.values] = HashChoices.MD5

    # utils

    @property
    def is_type_observable(self) -> bool:
        return self.type == TypeChoices.OBSERVABLE

    @property
    def is_type_file(self) -> bool:
        return self.type == TypeChoices.FILE

    def is_observable_type_supported(self, observable_classification: str) -> bool:
        return observable_classification in self.observable_supported

    def is_filetype_supported(self, file_mimetype: str) -> bool:
        return (
            file_mimetype in self.supported_filetypes
            or file_mimetype not in self.not_supported_filetypes
        )

    def get_full_import_path(self) -> str:
        if self.is_type_observable or (self.is_type_file and self.run_hash):
            return (
                f"api_app.analyzers_manager.observable_analyzers.{self.python_module}"
            )
        else:
            return f"api_app.analyzers_manager.file_analyzers.{self.python_module}"

    @classmethod
    def get(cls, analyzer_name: str) -> typing.Optional["AnalyzerConfig"]:
        """
        Returns config dataclass by analyzer_name if found, else None
        """
        all_configs = AnalyzerConfigSerializer.read_and_verify_config()
        config_dict = all_configs.get(analyzer_name, None)
        if config_dict is None:
            return None  # not found
        return cls.from_dict(config_dict)

    @classmethod
    def from_dict(cls, data: dict) -> "AnalyzerConfig":
        return cls(**data)

    @classmethod
    def all(cls) -> typing.Dict[str, "AnalyzerConfig"]:
        return {
            name: cls.from_dict(attrs)
            for name, attrs in AnalyzerConfigSerializer.read_and_verify_config().items()
        }
