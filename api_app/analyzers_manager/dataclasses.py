# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import typing
import dataclasses

from api_app.core.dataclasses import AbstractConfig
from .constants import TypeChoices, HashChoices, ObservableTypes


__all__ = ["AnalyzerConfig"]


@dataclasses.dataclass
class AnalyzerConfig(AbstractConfig):
    # Required fields
    type: typing.Literal[TypeChoices.aslist()]
    supported_filetypes: typing.List[str]
    not_supported_filetypes: typing.List[str]
    observable_supported: typing.List[typing.Literal[ObservableTypes.aslist()]]
    # Optional Fields
    external_service: bool = False
    leaks_info: bool = False
    run_hash: bool = False
    run_hash_type: typing.Literal[HashChoices.aslist()] = HashChoices.MD5.value

    # utils

    def is_type_observable(self) -> bool:
        return self.type == TypeChoices.OBSERVABLE.value

    def is_observable_type_supported(self, observable_classification: str) -> bool:
        return observable_classification in self.observable_supported

    def is_filetype_supported(self, file_mimetype: str) -> bool:
        return (
            file_mimetype in self.supported_filetypes
            and file_mimetype not in self.not_supported_filetypes
        )
