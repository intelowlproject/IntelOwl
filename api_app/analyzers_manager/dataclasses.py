# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import dataclasses
import logging
import re
import typing

from django.conf import settings

from api_app.core.dataclasses import AbstractConfig

from ..core.models import AbstractReport
from .constants import HashChoices, TypeChoices
from .serializers import AnalyzerConfigSerializer

__all__ = [
    "AnalyzerConfig",
]

logger = logging.getLogger(__name__)

REGEX_OFFICE_FILES = r"\.[xl|doc]\w{0,3}$"


@dataclasses.dataclass
class AnalyzerConfig(AbstractConfig):
    @classmethod
    def _get_report_model(cls) -> typing.Type[AbstractReport]:
        from api_app.analyzers_manager.models import AnalyzerReport

        return AnalyzerReport

    # Required fields
    type: typing.Literal["file", "observable"]
    supported_filetypes: typing.List[str]
    not_supported_filetypes: typing.List[str]
    observable_supported: typing.List[
        typing.Literal["ip", "url", "domain", "hash", "generic"]
    ]
    # Optional Fields
    external_service: bool = False
    leaks_info: bool = False
    docker_based: bool = False
    run_hash: bool = False
    run_hash_type: typing.Literal["md5", "sha256"] = HashChoices.MD5

    @classmethod
    def _get_serializer_class(cls) -> typing.Type[AnalyzerConfigSerializer]:
        return AnalyzerConfigSerializer

    # utils
    @property
    def is_type_observable(self) -> bool:
        return self.type == TypeChoices.OBSERVABLE

    @property
    def is_type_file(self) -> bool:
        return self.type == TypeChoices.FILE

    def is_observable_type_supported(self, observable_classification: str) -> bool:
        return observable_classification in self.observable_supported

    def is_filetype_supported(self, file_mimetype: str, file_name: str) -> bool:
        # PCAPs are not classic files. They should not leverage the default behavior.
        # We should execute them only if the analyzer specifically support them.
        special_pcap_mimetype = "application/vnd.tcpdump.pcap"
        if (
            file_mimetype == special_pcap_mimetype
            and special_pcap_mimetype not in self.supported_filetypes
        ):
            return False
        # Android only types to filter unwanted zip files
        if (
            "android_only" in self.supported_filetypes
            and file_mimetype == "application/zip"
            and re.search(REGEX_OFFICE_FILES, file_name)
        ):
            logger.info(
                f"filtered office file name {file_name}"
                " because the analyzer is android only"
            )
            return False
        # base case: empty lists means supports all
        if not self.supported_filetypes and not self.not_supported_filetypes:
            return True
        return (
            file_mimetype in self.supported_filetypes
            and file_mimetype not in self.not_supported_filetypes
        )

    def get_full_import_path(self) -> str:
        if self.is_type_observable or (self.is_type_file and self.run_hash):
            return (
                f"{settings.BASE_ANALYZER_OBSERVABLE_PYTHON_PATH}.{self.python_module}"
            )
        return f"{settings.BASE_ANALYZER_FILE_PYTHON_PATH}.{self.python_module}"
