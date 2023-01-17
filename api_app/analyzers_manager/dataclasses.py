# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import dataclasses
import logging
import re
import typing

from celery import uuid
from celery.canvas import Signature
from django.conf import settings

from api_app.core.dataclasses import AbstractConfig
from api_app.models import Job
from intel_owl.consts import DEFAULT_QUEUE

from ..models import PluginConfig
from .constants import HashChoices, TypeChoices
from .serializers import AnalyzerConfigSerializer

__all__ = [
    "AnalyzerConfig",
]

logger = logging.getLogger(__name__)

REGEX_OFFICE_FILES = "\.[xl|doc]\w{0,3}$"


@dataclasses.dataclass
class AnalyzerConfig(AbstractConfig):
    def _get_type(self) -> str:
        return PluginConfig.PluginType.ANALYZER

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
        ):
            if re.search(REGEX_OFFICE_FILES, file_name):
                logger.info(
                    f"filtered office file name {file_name}"
                    f" because the analyzer is android only"
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
                f"api_app.analyzers_manager.observable_analyzers.{self.python_module}"
            )
        return f"api_app.analyzers_manager.file_analyzers.{self.python_module}"

    @classmethod
    def from_dict(cls, data: dict) -> "AnalyzerConfig":
        return cls(**data)

    # orm methods

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
    def is_disabled(cls, class_name: str) -> bool:
        all_analyzer_config = cls.all()
        for name, ac in all_analyzer_config.items():
            if ac.python_module.endswith(f".{class_name}"):
                if not ac.disabled:
                    return False
        return True

    @classmethod
    def all(cls) -> typing.Dict[str, "AnalyzerConfig"]:
        return {
            name: cls.from_dict(attrs)
            for name, attrs in AnalyzerConfigSerializer.read_and_verify_config().items()
        }

    @classmethod
    def filter(cls, names: typing.List[str]) -> typing.Dict[str, "AnalyzerConfig"]:
        all_analyzer_config = cls.all()
        return {name: ac for name, ac in all_analyzer_config.items() if name in names}

    @staticmethod
    def runnable_analyzers(analyzers_to_execute: typing.List[str]) -> typing.List[str]:
        analyzer_dataclass = AnalyzerConfig.all()
        return [
            analyzer
            for analyzer in analyzers_to_execute
            if analyzer_dataclass.get(analyzer)
        ]

    @classmethod
    def stack_analyzers(
        cls,
        job_id: int,
        analyzers_to_execute: typing.List[str],
        runtime_configuration: typing.Dict[str, typing.Dict] = None,
        parent_playbook="",
    ) -> typing.Tuple[typing.List[Signature], typing.List[str]]:
        from intel_owl import tasks

        # to store the celery task signatures
        task_signatures = []
        analyzers_used = []

        analyzers_to_run = cls.runnable_analyzers(
            analyzers_to_execute=analyzers_to_execute
        )

        analyzer_dataclasses = cls.all()

        # get job
        job = Job.objects.get(pk=job_id)
        job.update_status(Job.Status.RUNNING)  # set job status to running

        # loop over and create task signatures
        for a_name in analyzers_to_run:
            # get corresponding dataclass
            config = analyzer_dataclasses.get(a_name, None)

            # if disabled or unconfigured (this check is bypassed in STAGE_CI)
            if not config.is_ready_to_use and not settings.STAGE_CI:
                logger.info(f"skipping execution of analyzer {a_name}, job_id {job_id}")
                continue

            # get runtime_configuration if any specified for this analyzer
            runtime_params = runtime_configuration.get(a_name, {})
            # gen new task_id
            task_id = uuid()
            # construct arguments
            args = [
                job_id,
                config.asdict(),
                {"runtime_configuration": runtime_params, "task_id": task_id},
                parent_playbook,
            ]
            # get celery queue
            queue = config.config.queue
            if queue not in settings.CELERY_QUEUES:
                logger.warning(
                    f"Analyzer {a_name} has a wrong queue."
                    f" Setting to `{DEFAULT_QUEUE}`"
                )
                queue = DEFAULT_QUEUE
            # get soft_time_limit
            soft_time_limit = config.config.soft_time_limit
            # create task signature and add to list
            task_signatures.append(
                tasks.run_analyzer.signature(
                    args,
                    {},
                    queue=queue,
                    soft_time_limit=soft_time_limit,
                    task_id=task_id,
                )
            )
            analyzers_used.append(a_name)

        return task_signatures, analyzers_used
