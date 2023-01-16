# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import typing
from typing import Dict, List

from celery import group
from rest_framework.exceptions import ValidationError

from .classes import Connector
from .dataclasses import ConnectorConfig
from .models import ConnectorReport

logger = logging.getLogger(__name__)


def start_connectors(
    job_id: int,
    connectors_to_execute: List[str],
    runtime_configuration: Dict[str, Dict] = None,
) -> None:

    # we should not use mutable objects as default to avoid unexpected issues
    if runtime_configuration is None:
        runtime_configuration = {}

    cleaned_result = ConnectorConfig.stack(
        job_id=job_id,
        plugins_to_execute=connectors_to_execute,
        runtime_configuration=runtime_configuration,
    )

    task_signatures = cleaned_result[0]

    # fire the connectors in a grouped celery task
    # https://docs.celeryproject.org/en/stable/userguide/canvas.html
    mygroup = group(task_signatures)
    mygroup()

    return None


def set_failed_connector(
    job_id: int, name: str, err_msg: str, **report_defaults
) -> ConnectorReport:
    status = ConnectorReport.Status.FAILED
    logger.warning(f"({name}, job_id #{job_id}) -> set as {status}. Error: {err_msg}")
    report, _ = ConnectorReport.objects.get_or_create(
        job_id=job_id, name=name, defaults=report_defaults
    )
    report.status = status
    report.errors.append(err_msg)
    report.save()
    return report


def run_connector(
    job_id: int, config_dict: dict, report_defaults: dict, parent_playbook: str = ""
) -> ConnectorReport:
    config = ConnectorConfig.from_dict(config_dict)
    try:
        class_ = config.get_class()
    except ImportError as e:
        report = set_failed_connector(job_id, config.name, str(e), **report_defaults)
    else:
        instance = class_(config=config, job_id=job_id, report_defaults=report_defaults)
        report = instance.start(parent_playbook)

    return report


def run_healthcheck(connector_name: str) -> bool:
    connector_config = ConnectorConfig.get(connector_name)
    if connector_config is None:
        raise ValidationError({"detail": "Connector doesn't exist"})

    class_: typing.Type[Connector] = connector_config.get_class()

    try:
        status = class_.health_check(connector_name)
    except NotImplementedError:
        raise ValidationError({"detail": "No healthcheck implemented"})

    return status
