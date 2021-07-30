# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import Union, List, Dict
from celery import uuid

from django.conf import settings
from django.utils.module_loading import import_string
from intel_owl.celery import app as celery_app

from .serializers import ConnectorConfigSerializer
from .dataclasses import ConnectorConfig
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

    # get connectors config
    connectors_config = ConnectorConfigSerializer.get_as_dataclasses()
    if not connector_names == ALL_CONNECTORS:
        # filter/ select only the ones that were specified
        connectors_config = {
            name: cc
            for name, cc in connectors_config.items()
            if name in connector_names
        }

    # loop over and fire the connectors in a celery task
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
        stl = cc.params.soft_time_limit
        # add to map
        connectors_task_id_map[connector_name] = task_id
        # fire celery task to run connector
        celery_app.send_task(
            CELERY_TASK_NAME,
            args=args,
            kwargs=kwargs,
            queue=queue,
            soft_time_limit=stl,
            task_id=task_id,
        )

    return connectors_task_id_map


def set_failed_connector(job_id: int, name: str, err_msg: str):
    status = ConnectorReport.Statuses.FAILED.name
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


def run_connector(job_id: int, config: ConnectorConfig, **kwargs) -> Connector:
    instance = None
    try:
        cls_path = config.get_full_import_path()
        try:
            klass: Connector = import_string(cls_path)
        except ImportError:
            raise Exception(f"Class: {cls_path} couldn't be imported")

        instance = klass(config=config, job_id=job_id, **kwargs)
        instance.start()
    except Exception as e:
        set_failed_connector(job_id, config.name, str(e))

    return instance
