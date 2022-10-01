# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import dataclasses
import logging
import typing

from celery import uuid
from celery.canvas import Signature
from django.conf import settings

from api_app.core.dataclasses import AbstractConfig
from intel_owl.consts import DEFAULT_QUEUE

from .serializers import ConnectorConfigSerializer

__all__ = ["ConnectorConfig"]

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class ConnectorConfig(AbstractConfig):
    maximum_tlp: str

    serializer_class = ConnectorConfigSerializer

    def get_full_import_path(self) -> str:
        return f"api_app.connectors_manager.connectors.{self.python_module}"

    @classmethod
    def from_dict(cls, data: dict) -> "ConnectorConfig":
        return cls(**data)

    # orm methods

    @classmethod
    def get(cls, connector_name: str) -> typing.Optional["ConnectorConfig"]:
        """
        Returns config dataclass by connector_name if found, else None
        """
        all_configs = cls.serializer_class.read_and_verify_config()
        config_dict = all_configs.get(connector_name, None)
        if config_dict is None:
            return None  # not found
        return cls.from_dict(config_dict)

    @classmethod
    def all(cls) -> typing.Dict[str, "ConnectorConfig"]:
        return {
            name: cls.from_dict(attrs)
            for name, attrs in cls.serializer_class.read_and_verify_config().items()
        }

    @classmethod
    def filter(cls, names: typing.List[str]) -> typing.Dict[str, "ConnectorConfig"]:
        all_connector_configs = cls.all()
        return {name: cc for name, cc in all_connector_configs.items() if name in names}

    @staticmethod
    def runnable_connectors(
        connectors_to_execute: typing.List[str],
    ) -> typing.List[str]:
        connector_dataclass = ConnectorConfig.all()
        return [
            connector
            for connector in connectors_to_execute
            if connector_dataclass.get(connector).is_ready_to_use and settings.STAGE_CI
        ]

    @classmethod
    def stack_connectors(
        cls,
        job_id: int,
        connectors_to_execute: typing.List[str],
        runtime_configuration: typing.Dict[str, typing.Dict] = None,
        parent_playbook="",
    ) -> typing.Tuple[typing.List[Signature], typing.List[str]]:
        from intel_owl import tasks

        # to store the celery task signatures
        task_signatures = []

        connectors_used = []
        connectors_to_run = cls.runnable_connectors(connectors_to_execute)

        # get connectors config
        connector_dataclasses = cls.filter(names=connectors_to_run)

        # loop over and create task signatures
        for c_name, cc in connector_dataclasses.items():
            # if disabled or unconfigured (this check is bypassed in STAGE_CI)
            if not cc.is_ready_to_use and not settings.STAGE_CI:
                continue

            # get runtime_configuration if any specified for this analyzer
            runtime_params = runtime_configuration.get(c_name, {})
            # gen a new task_id
            task_id = uuid()
            # construct args
            args = [
                job_id,
                cc.asdict(),
                {"runtime_configuration": runtime_params, "task_id": task_id},
                parent_playbook,
            ]
            # get celery queue
            queue = cc.config.queue
            if queue not in settings.CELERY_QUEUES:
                logger.error(
                    f"Connector {c_name} has a wrong queue."
                    f" Setting to `{DEFAULT_QUEUE}`"
                )
                queue = DEFAULT_QUEUE
            # get soft_time_limit
            soft_time_limit = cc.config.soft_time_limit
            # create task signature and add to list
            task_signatures.append(
                tasks.run_connector.signature(
                    args,
                    {},
                    queue=queue,
                    soft_time_limit=soft_time_limit,
                    task_id=task_id,
                    ignore_result=True,  # since we are using group and not chord
                )
            )
            connectors_used.append(c_name)

        return task_signatures, connectors_used
