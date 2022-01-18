# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import Dict, List

from celery import group, uuid
from django.conf import settings
from django.utils.module_loading import import_string
from rest_framework.exceptions import ValidationError

from api_app.exceptions import NotRunnableConnector
from api_app.models import TLP
from intel_owl.consts import DEFAULT_QUEUE

from .classes import Connector
from .dataclasses import ConnectorConfig
from .models import ConnectorReport

logger = logging.getLogger(__name__)


def filter_connectors(serialized_data: Dict, warnings: List[str]) -> List[str]:
    # init empty list
    cleaned_connectors_list = []
    selected_connectors = []

    # get values from serializer
    connectors_requested = serialized_data.get("connectors_requested", [])
    tlp = serialized_data.get("tlp", TLP.WHITE).upper()

    # read config
    connector_dataclasses = ConnectorConfig.all()
    all_connector_names = list(connector_dataclasses.keys())

    # run all connectors ?
    run_all = len(connectors_requested) == 0
    if run_all:
        # select all
        selected_connectors.extend(all_connector_names)
    else:
        # select the ones requested
        selected_connectors.extend(connectors_requested)

    for c_name in selected_connectors:
        try:
            cc = connector_dataclasses.get(c_name, None)

            if not cc:
                if not run_all:
                    raise NotRunnableConnector(
                        f"{c_name} won't run: not available in configuration"
                    )
                # don't add warning if run_all
                continue

            if not cc.is_ready_to_use:  # check configured/disabled
                raise NotRunnableConnector(
                    f"{c_name} won't run: is disabled or unconfigured"
                )

            if TLP.get_priority(tlp) > TLP.get_priority(
                cc.maximum_tlp
            ):  # check if job's tlp allows running
                # e.g. if connector_tlp is GREEN(1),
                # run for job_tlp WHITE(0) & GREEN(1) only
                raise NotRunnableConnector(
                    f"{c_name} won't run: "
                    f"job.tlp ('{tlp}') > maximum_tlp ('{cc.maximum_tlp}')"
                )
        except NotRunnableConnector as e:
            if run_all:
                # in this case, they are not warnings but expected and wanted behavior
                logger.debug(e)
            else:
                logger.warning(e)
                warnings.append(str(e))
        else:
            cleaned_connectors_list.append(c_name)

    return cleaned_connectors_list


def start_connectors(
    job_id: int,
    connectors_to_execute: List[str],
    runtime_configuration: Dict[str, Dict] = None,
) -> None:
    from intel_owl import tasks

    # we should not use mutable objects as default to avoid unexpected issues
    if runtime_configuration is None:
        runtime_configuration = {}

    # to store the celery task signatures
    task_signatures = []

    # get connectors config
    connector_dataclasses = ConnectorConfig.filter(names=connectors_to_execute)

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
    job_id: int, config_dict: dict, report_defaults: dict
) -> ConnectorReport:
    config = ConnectorConfig.from_dict(config_dict)
    klass: Connector = None
    report: ConnectorReport = None
    try:
        cls_path = config.get_full_import_path()
        try:
            klass = import_string(cls_path)
        except ImportError:
            raise Exception(f"Class: {cls_path} couldn't be imported")

        instance = klass(config=config, job_id=job_id, report_defaults=report_defaults)
        report = instance.start()
    except Exception as e:
        report = set_failed_connector(job_id, config.name, str(e), **report_defaults)

    return report


def run_healthcheck(connector_name: str) -> bool:
    connector_config = ConnectorConfig.get(connector_name)
    if connector_config is None:
        raise ValidationError({"detail": "Connector doesn't exist"})

    cls_path = connector_config.get_full_import_path()
    try:
        klass: Connector = import_string(cls_path)
    except ImportError:
        raise Exception(f"Class: {cls_path} couldn't be imported")

    status = None
    try:
        status = klass.health_check(connector_name)
    except NotImplementedError:
        raise ValidationError({"detail": "No healthcheck implemented"})

    return status
