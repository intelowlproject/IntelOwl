# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import re
from logging import getLogger
from typing import Type

from django.conf import settings
from django.contrib.postgres import fields as pg_fields
from django.core.exceptions import ValidationError
from django.db import models

from api_app.analyzers_manager.constants import (
    HashChoices,
    ObservableTypes,
    TypeChoices,
)
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
    supported_filetypes = pg_fields.ArrayField(
        models.CharField(null=False, max_length=90), default=list, blank=True
    )
    run_hash = models.BooleanField(default=False)
    run_hash_type = models.CharField(
        blank=True, choices=HashChoices.choices, max_length=10
    )
    not_supported_filetypes = pg_fields.ArrayField(
        models.CharField(null=False, max_length=90), default=list, blank=True
    )

    REGEX_OFFICE_FILES = r"\.[xl|doc]\w{0,3}$"

    def clean(self):
        super().clean()
        self.clean_run_hash_type()

    def clean_run_hash_type(self):
        if self.run_hash and not self.run_hash_type:
            raise ValidationError("run_hash_type must be populated if run_hash is True")

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
            and re.search(self.REGEX_OFFICE_FILES, file_name)
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

    @classmethod
    def _get_type(cls) -> str:
        return PluginConfig.PluginType.ANALYZER

    @classmethod
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
        else:
            logger.error(f"Unable to update {python_module}")
            return False
