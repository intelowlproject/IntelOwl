# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import json
from logging import getLogger
from typing import Dict, Optional, Type, Union

from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import models

from api_app.analyzers_manager.constants import HashChoices, TypeChoices
from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException
from api_app.analyzers_manager.queryset import AnalyzerReportQuerySet
from api_app.choices import TLP, Classification, PythonModuleBasePaths
from api_app.data_model_manager.fields import SetField
from api_app.data_model_manager.models import BaseDataModel
from api_app.fields import ChoiceArrayField
from api_app.models import AbstractReport, PythonConfig, PythonModule

logger = getLogger(__name__)


class AnalyzerReport(AbstractReport):
    objects = AnalyzerReportQuerySet.as_manager()
    config = models.ForeignKey(
        "AnalyzerConfig", related_name="reports", null=False, on_delete=models.CASCADE
    )
    data_model_content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        limit_choices_to={
            "app_label": "data_model_manager",
        },
        null=True,
        editable=False,
        blank=True,
    )
    data_model_object_id = models.IntegerField(null=True, editable=False, blank=True)
    data_model = GenericForeignKey("data_model_content_type", "data_model_object_id")

    class Meta:
        unique_together = [("config", "job")]
        indexes = AbstractReport.Meta.indexes + [
            models.Index(fields=["data_model_content_type", "data_model_object_id"])
        ]

    def clean(self):
        if (
            self.data_model_content_type
            and ContentType.objects.get_for_model(model=self.data_model_class)
            != self.data_model_content_type
        ):
            raise ValidationError("Wrong data model for this report")

    @property
    def data_model_class(self) -> Type[BaseDataModel]:
        return self.job.analyzable.get_data_model_class()

    def _validation_before_data_model(self) -> bool:
        if not self.status == self.STATUSES.SUCCESS.value:
            logger.info(
                f"Skipping data model of {self.config.name} for job {self.config_id} because status is "
                f"{self.status}"
            )
            return False
        data_model_keys = self.data_model_class.get_fields().keys()
        for data_model_key in self.config.mapping_data_model.values():
            if data_model_key not in data_model_keys:
                self.errors.append(
                    f"Field {data_model_key} not available in {self.data_model_class.__name__}"
                )
        return True

    def _create_data_model_dictionary(self) -> Dict:
        """
        Returns a dictionary that will be used to create an initial data model for the report.

        It uses the mapping_data_model field of the AnalyzerConfig to map the fields of the report with the fields of the data model.

        For example, if we have

        analyzer_report = {
            "family": "MalwareFamily"
        }

        mapping_data_model = {"family": "malware_family"}

        the method returns
        result = {"malware_family": "MalwareFamily"}.
        """
        result = {}
        logger.debug(f"Mapping is {json.dumps(self.config.mapping_data_model)}")
        for report_key, data_model_key in self.config.mapping_data_model.items():
            # this is a constant
            if report_key.startswith("$"):
                value = report_key[1:]
            elif isinstance(report_key, int):
                value = report_key
            # this is a field of the report
            else:
                try:
                    value = self.get_value(self.report, report_key.split("."))
                    logger.debug(f"Retrieved {value} from key {report_key}")
                except Exception:
                    # validation
                    self.errors.append(f"Field {report_key} not available in report")
                    continue
            fields = self.data_model_class.get_fields()
            if isinstance(fields[data_model_key], SetField):
                try:
                    if isinstance(value, list):
                        result[data_model_key].extend(value)
                    else:
                        result[data_model_key].append(value)
                except KeyError:
                    if isinstance(value, list):
                        result[data_model_key] = value
                    else:
                        result[data_model_key] = [value]
            else:
                result[data_model_key] = value
        return result

    def create_data_model(self) -> Optional[BaseDataModel]:
        # TODO we don't need to actually crate a new object every time.
        #  if the report is the same of the previous one, we can just link it
        if not self._validation_before_data_model():
            return None
        dictionary = self._create_data_model_dictionary()

        self.data_model: BaseDataModel = self.data_model_class.objects.create()
        self.data_model.merge(dictionary)
        self.save()
        return self.data_model


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
    EXECUTABLE = "application/x-executable"
    JAVA2 = "text/x-java"
    KOTLIN = "text/x-kotlin"
    SWIFT = "text/x-swift"
    OBJECTIVE_C_CODE = "text/x-objective-c"
    LNK = "application/x-ms-shortcut"
    GZIP = "application/gzip"

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
        elif file_name.endswith(".java"):
            mimetype = cls.JAVA2
        elif file_name.endswith(".swift"):
            mimetype = cls.SWIFT
        elif file_name.endswith(".kt"):
            mimetype = cls.KOTLIN
        elif file_name.endswith(".m"):
            mimetype = cls.OBJECTIVE_C_CODE

        else:
            return None
        return mimetype

    @classmethod
    def calculate(cls, buffer: Union[bytes, str], file_name: str) -> str:
        from magic import from_buffer as magic_from_buffer

        mimetype = None
        if file_name:
            mimetype = cls._calculate_from_filename(file_name)

        if mimetype is None:
            mimetype = magic_from_buffer(
                buffer.encode() if isinstance(buffer, str) else buffer, mime=True
            )
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
        models.CharField(
            null=False, choices=Classification.choices[:-1], max_length=30
        ),
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
    mapping_data_model = models.JSONField(
        default=dict,
        help_text="Mapping analyzer_report_key: data_model_key. Keys preceded by the symbol $ will be considered as constants.",
        blank=True,
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


class AnalyzerRulesFileVersion(models.Model):
    last_downloaded_version = models.CharField(max_length=50, blank=True, default="")
    download_url = models.URLField(max_length=200, blank=True, default="")
    downloaded_at = models.DateTimeField(auto_now_add=True)

    python_module = models.ForeignKey(
        PythonModule, on_delete=models.PROTECT, related_name="rules_version"
    )
