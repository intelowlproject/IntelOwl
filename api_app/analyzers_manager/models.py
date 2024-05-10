# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from logging import getLogger
from typing import Optional

from django.contrib.contenttypes.fields import GenericRelation
from django.core.exceptions import ValidationError
from django.db import models

from api_app.analyzers_manager.constants import (
    HashChoices,
    ObservableTypes,
    TypeChoices,
)
from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException
from api_app.analyzers_manager.queryset import AnalyzerReportQuerySet
from api_app.choices import TLP, PythonModuleBasePaths
from api_app.fields import ChoiceArrayField
from api_app.models import AbstractReport, PythonConfig, PythonModule

logger = getLogger(__name__)


class AnalyzerReport(AbstractReport):
    objects = AnalyzerReportQuerySet.as_manager()
    config = models.ForeignKey(
        "AnalyzerConfig", related_name="reports", null=False, on_delete=models.CASCADE
    )

    class Meta:
        unique_together = [("config", "job")]
        indexes = AbstractReport.Meta.indexes


class MimeTypes(models.TextChoices):
    # IMPORTANT! in case you update this Enum remember to update also the frontend
    WSCRIPT = "application/w-script-file"
    JAVASCRIPT1 = "application/javascript"
    JAVASCRIPT2 = "application/x-javascript"
    JAVASCRIPT3 = "text/javascript"
    VB_SCRIPT = "application/x-vbscript"
    IQY = "text/x-ms-iqy"
    APK = "application/vnd.android.package-archive"
    DEX = "application/x-dex"
    ONE_NOTE = "application/onenote"
    ZIP1 = "application/zip"
    ZIP2 = "multipart/x-zip"
    JAVA = "application/java-archive"
    RTF1 = "text/rtf"
    RTF2 = "application/rtf"
    SHARED_LIB = "application/x-sharedlib"
    EXE = "application/vnd.microsoft.portable-executable"
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
    MAC3 = "application/x-mach-binary"
    COMPRESS1 = "application/x-zip-compressed"
    COMPRESS2 = "application/x-compressed"
    OUTLOOK = "application/vnd.ms-outlook"
    EML = "message/rfc822"
    PKCS7 = "application/pkcs7-signature"
    XPKCS7 = "application/x-pkcs7-signature"
    MIXED = "multipart/mixed"
    X_SHELLSCRIPT = "text/x-shellscript"
    CRX = "application/x-chrome-extension"
    JSON = "application/json"

    @classmethod
    def _calculate_from_filename(cls, file_name: str) -> Optional["MimeTypes"]:
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
        else:
            return None
        return mimetype

    @classmethod
    def calculate(cls, file_pointer, file_name) -> str:
        from magic import from_buffer as magic_from_buffer

        mimetype = None
        if file_name:
            mimetype = cls._calculate_from_filename(file_name)

        if mimetype is None:
            buffer = file_pointer.read()
            mimetype = magic_from_buffer(buffer, mime=True)
            logger.debug(f"mimetype is {mimetype}")
            try:
                mimetype = cls(mimetype)
            except ValueError:
                logger.info(
                    f"Unable to valid a {cls.__name__} for mimetype {mimetype}"
                    f" for file {file_name}"
                )
            else:
                mimetype = mimetype.value

        return mimetype


class AnalyzerConfig(PythonConfig):
    # generic
    type = models.CharField(choices=TypeChoices.choices, null=False, max_length=50)
    docker_based = models.BooleanField(null=False, default=False)
    maximum_tlp = models.CharField(
        null=False, default=TLP.RED, choices=TLP.choices, max_length=50
    )
    python_module = models.ForeignKey(
        PythonModule,
        on_delete=models.PROTECT,
        related_name="%(class)ss",
        limit_choices_to={
            "base_path__in": [
                PythonModuleBasePaths.FileAnalyzer.value,
                PythonModuleBasePaths.ObservableAnalyzer.value,
            ]
        },
    )
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
    orgs_configuration = GenericRelation(
        "api_app.OrganizationPluginConfiguration", related_name="%(class)s"
    )

    @classmethod
    @property
    def serializer_class(cls):
        from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer

        return AnalyzerConfigSerializer

    def clean_observable_supported(self):
        if self.type == TypeChoices.OBSERVABLE and not self.observable_supported:
            raise ValidationError(
                "You have to specify at least one type of observable supported"
            )
        if self.type != TypeChoices.OBSERVABLE and self.observable_supported:
            raise ValidationError(
                "You can't specify an observable type if you do not support observable"
            )

    def clean_filetypes(self):
        if self.type == TypeChoices.FILE:
            if self.supported_filetypes and self.not_supported_filetypes:
                raise ValidationError(
                    "Please specify only one between "
                    "supported_filetypes and not_supported_filetypes"
                )
        else:
            if self.supported_filetypes or self.not_supported_filetypes:
                raise ValidationError(
                    "You can't specify supported_filetypes or "
                    "not_supported_filetypes if you do not support files"
                )

    def clean_run_hash_type(self):
        if self.run_hash and not self.run_hash_type:
            raise ValidationError("run_hash_type must be populated if run_hash is True")

    def clean(self):
        super().clean()
        self.clean_run_hash_type()
        self.clean_observable_supported()
        self.clean_filetypes()

    @classmethod
    @property
    def plugin_type(cls) -> str:
        return "1"

    @classmethod
    @property
    def config_exception(cls):
        return AnalyzerConfigurationException
