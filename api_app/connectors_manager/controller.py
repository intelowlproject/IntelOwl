# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import typing
from typing import Dict, List

from celery import group
from rest_framework.exceptions import ValidationError

from .classes import Connector
from .dataclasses import ConnectorConfig

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
