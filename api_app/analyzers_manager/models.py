# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import re
from logging import getLogger
from typing import List, Type

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from api_app.analyzers_manager.constants import (
    HashChoices,
    ObservableTypes,
    TypeChoices,
)
from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException
from api_app.core.models import AbstractConfig, AbstractReport
from api_app.fields import ChoiceArrayField
from api_app.models import PluginConfig

logger = getLogger(__name__)


class AnalyzerReport(AbstractReport):
    job = models.ForeignKey(
        "api_app.Job", related_name="analyzer_reports", on_delete=models.CASCADE
    )

    class Meta:
        unique_together = [("name", "job")]

    @property
    def analyzer_name(self) -> str:
        return self.name


class MimeTypes(models.TextChoices):

    JAVASCRIPT1 = "application/javascript"
    JAVASCRIPT2 = "application/x-javascript"
    JAVASCRIPT3 = "text/javascript"

    VB_SCRIPT = "application/x-vbscript"
    IQY = "text/x-ms-iqy"
    APK = "application/vnd.android.package-archive"
    DEX = "application/x-dex"
    ONE_NOTE = "application/onenote"
    ANDROID = "android"
    ZIP1 = "application/zip"
    ZIP2 = "multipart/x-zip"
    JAVA = "application/java-archive"
    RTF1 = "text/rtf"
    RTF2 = "application/rtf"
    DOS = "application/x-dosexec"
    SHARED_LIB = "application/x-sharedlib"
    EXE = "application/x-executable"
    ELF = "application/x-elf"
    OCTET = "application/octet-stream"
    PCAP = "application/vnd.tcpdump.pcap"
    PDF = "application/pdf"
    HTML = "text/html"
    PUB = "application/x-mspublisher"
    EXCEL_MACRO1 = "application/vnd.ms-excel.addin.macroEnabled"
    EXCEL_MACRO2 = "application/vnd.ms-excel.sheet.macroEnabled.12"
    EXCEL1 = "application/vnd.ms-excel"
    EXCEL2 = "application/excel"
    DOC = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    XML1 = "application/xml"
    XML2 = "text/xml"
    ENCRYPTED = "application/encrypted"
    PLAIN = "text/plain"
    CSV = "text/csv"
    PPTX = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    WORD1 = "application/msword"
    WORD2 = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    POWERPOINT = "application/vnd.ms-powerpoint"
    OFFICE = "application/vnd.ms-office"
    BINARY = "application/x-binary"
    MAC1 = "application/x-macbinary"
    MAC2 = "application/mac-binary"
    COMPRESS1 = "application/x-zip-compressed"
    COMPRESS2 = "application/x-compressed"

    @classmethod
    def ZIP(cls) -> List["MimeTypes"]:
        return [cls.ZIP1, cls.ZIP2]

    @classmethod
    def WORD(cls) -> List["MimeTypes"]:
        return [cls.WORD1, cls.WORD2]

    @classmethod
    def calculate(cls, file_pointer, file_name) -> str:
        from magic import from_buffer as magic_from_buffer

        REGEX_OFFICE_FILES = r"\.[xl|doc]\w{0,3}$"

        mimetype = None
        if file_name:
            if file_name.endswith(".js") or file_name.endswith(".jse"):
                mimetype = cls.JAVASCRIPT1
            elif file_name.endswith(".vbs") or file_name.endswith(".vbe"):
                mimetype = cls.VB_SCRIPT
            elif file_name.endswith(".iqy"):
                mimetype = cls.IQY
            elif file_name.endswith(".apk"):
                mimetype = cls.APK
            elif file_name.endswith(".dex"):
                mimetype = cls.DEX
            elif file_name.endswith(".one"):
                mimetype = cls.ONE_NOTE

        if not mimetype:
            buffer = file_pointer.read()
            mimetype = magic_from_buffer(buffer, mime=True)
            logger.debug(f"mimetype is {mimetype}")
            mimetype = cls(mimetype)

        if mimetype in cls.ZIP and re.search(REGEX_OFFICE_FILES, file_name):
            return cls.ANDROID

        return mimetype


class AnalyzerConfig(AbstractConfig):
    # generic
    type = models.CharField(choices=TypeChoices.choices, null=False, max_length=50)
    docker_based = models.BooleanField(null=False, default=False)
    external_service = models.BooleanField(null=False, default=True)
    leaks_info = models.BooleanField(null=False)
    # obs
    observable_supported = ChoiceArrayField(
        models.CharField(null=False, choices=ObservableTypes.choices, max_length=30),
        default=list,
        blank=True,
    )

    # file
    supported_filetypes = ChoiceArrayField(
        models.CharField(null=False, max_length=90, choices=MimeTypes.choices),
        default=list,
        blank=True,
    )
    run_hash = models.BooleanField(default=False)
    run_hash_type = models.CharField(
        blank=True, choices=HashChoices.choices, max_length=10
    )
    not_supported_filetypes = ChoiceArrayField(
        models.CharField(null=False, max_length=90, choices=MimeTypes.choices),
        default=list,
        blank=True,
    )

    def clean(self):
        super().clean()
        self.clean_run_hash_type()

    def clean_run_hash_type(self):
        if self.run_hash and not self.run_hash_type:
            raise ValidationError("run_hash_type must be populated if run_hash is True")

    @classmethod
    def _get_type(cls) -> str:
        return PluginConfig.PluginType.ANALYZER

    @classmethod
    @property
    def config_exception(cls):
        return AnalyzerConfigurationException

    @classmethod
    @property
    def report_model(cls) -> Type[AnalyzerReport]:
        return AnalyzerReport

    @property
    def python_path(self) -> str:
        if self.type == TypeChoices.FILE:
            return settings.BASE_ANALYZER_FILE_PYTHON_PATH
        else:
            return settings.BASE_ANALYZER_OBSERVABLE_PYTHON_PATH

    @classmethod
    def update(cls, python_module: str):
        from intel_owl.celery import broadcast

        analyzer_configs = AnalyzerConfig.objects.filter(python_module=python_module)
        for analyzer_config in analyzer_configs:
            analyzer_config: AnalyzerConfig
            if analyzer_config.is_runnable():
                class_ = analyzer_config.python_class
                if hasattr(class_, "_update") and callable(class_._update):
                    broadcast(
                        "update_plugin",
                        queue=analyzer_config.queue,
                        arguments={
                            "plugin_path": f"{analyzer_config.python_path}"
                            f".{analyzer_config.python_module}"
                        },
                    )
                    return True

        logger.error(f"Unable to update {python_module}")
        return False
