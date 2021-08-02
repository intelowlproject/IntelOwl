# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import Union, List, Dict
from celery import uuid, signature, group

from django.conf import settings
from django.utils.module_loading import import_string
from .serializers import ConnectorConfigSerializer
from .models import ConnectorReport
from .classes import Connector

logger = logging.getLogger(__name__)


# constants
CELERY_TASK_NAME = "run_connector"
ALL_CONNECTORS = "__all__"
DEFAULT_QUEUE = "default"
DEFAULT_SOFT_TIME_LIMIT = 300


def build_cache_key(job_id: int) -> str:
    return f"job.{job_id}.connector_manager.task_ids"


def start_connectors(
    job_id: int,
    connector_names: Union[List, str] = ALL_CONNECTORS,
    runtime_configuration: Dict[str, Dict] = None,
) -> Dict[str, str]:
    # we should not use mutable objects as default to avoid unexpected issues
    if runtime_configuration is None:
        runtime_configuration = {}

    # mapping of connector name and task_id
    connectors_task_id_map = {}
    # to store the celery task signatures
    task_signatures = []

    # get connectors config
    connectors_config = ConnectorConfigSerializer.get_as_dataclasses()
    if not connector_names == ALL_CONNECTORS:
        # filter/ select only the ones that were specified
        connectors_config = {
            name: cc
            for name, cc in connectors_config.items()
            if name in connector_names
        }

    # loop over and create task signatures
    for connector_name, cc in connectors_config.items():
        if not cc.is_ready_to_use:
            # skip this connector
            continue

        # get runtime_configuration if any specified for this analyzer
        runtime_conf = runtime_configuration.get(connector_name, {})
        # merge runtime_conf
        cc.config = {
            **cc.config,
            **runtime_conf,
        }
        # gen a new task_id
        task_id = uuid()
        # construct args
        args = [job_id, cc.asdict()]
        kwargs = {"runtime_conf": runtime_conf, "task_id": task_id}
        # get celery queue
        queue = cc.params.queue
        if queue not in settings.CELERY_QUEUES:
            logger.error(
                f"Connector {connector_name} has a wrong queue."
                f" Setting to `{DEFAULT_QUEUE}`"
            )
            queue = DEFAULT_QUEUE
        # get soft_time_limit
        soft_time_limit = cc.params.soft_time_limit
        # add to map
        connectors_task_id_map[connector_name] = task_id
        # create task signature and add to list
        task_signatures.append(
            signature(
                CELERY_TASK_NAME,
                args=args,
                kwargs=kwargs,
                queue=queue,
                soft_time_limit=soft_time_limit,
                task_id=task_id,
                ignore_result=True,  # since we are using group and not chord
            )
        )

    # fire the connectors in a grouped celery task
    # https://docs.celeryproject.org/en/stable/userguide/canvas.html
    mygroup = group(task_signatures)
    mygroup()

    return connectors_task_id_map


def set_failed_connector(job_id: int, name: str, err_msg: str) -> ConnectorReport:
    status = ConnectorReport.Status.FAILED
    logger.warning(
        f"({name}, job_id #{job_id}) -> set as {status}. " f" Error: {err_msg}"
    )
    report = ConnectorReport.objects.create(
        job_id=job_id,
        name=name,
        report={},
        errors=[err_msg],
        status=status,
    )
    return report


def run_connector(job_id: int, config_dict: dict, **kwargs) -> ConnectorReport:
    config = ConnectorConfigSerializer.dict_to_dataclass(config_dict)
    try:
        cls_path = config.get_full_import_path()
        try:
            klass: Connector = import_string(cls_path)
        except ImportError:
            raise Exception(f"Class: {cls_path} couldn't be imported")

        instance = klass(config=config, job_id=job_id, **kwargs)
        report = instance.start()
    except Exception as e:
        report = set_failed_connector(job_id, config.name, str(e))

    return report
