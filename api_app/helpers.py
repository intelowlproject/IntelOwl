# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# general helper functions used by the Django API

import hashlib
import ipaddress
import logging
import random
import re
from typing import Dict, List, Tuple
from celery import uuid
from django.conf import settings
from api_app.connectors_manager.dataclasses import ConnectorConfig

from intel_owl import tasks

from django.utils import timezone
from api_app.analyzers_manager.dataclasses import AnalyzerConfig
from api_app.exceptions import NotRunnableAnalyzer
from api_app.models import Job
from intel_owl.consts import DEFAULT_QUEUE
from magic import from_buffer as magic_from_buffer
from celery.canvas import Signature

from api_app.analyzers_manager.constants import ObservableTypes

logger = logging.getLogger(__name__)


def get_now_str():
    return str(timezone.now())


def get_now():
    return timezone.now()


def gen_random_colorhex() -> str:
    # flake8: noqa
    r = lambda: random.randint(0, 255)
    return "#%02X%02X%02X" % (r(), r(), r())


def calculate_mimetype(file_pointer, file_name) -> str:
    mimetype = None
    if file_name:
        if file_name.endswith(".js") or file_name.endswith(".jse"):
            mimetype = "application/javascript"
        elif file_name.endswith(".vbs") or file_name.endswith(".vbe"):
            mimetype = "application/x-vbscript"
        elif file_name.endswith(".iqy"):
            mimetype = "text/x-ms-iqy"
        elif file_name.endswith(".apk"):
            mimetype = "application/vnd.android.package-archive"
        elif file_name.endswith(".dex"):
            mimetype = "application/x-dex"

    if not mimetype:
        buffer = file_pointer.read()
        mimetype = magic_from_buffer(buffer, mime=True)

    return mimetype


def calculate_observable_classification(value: str) -> str:
    """Returns observable classification for the given value.\n
    Only following types are supported:
    ip, domain, url, hash (md5, sha1, sha256), generic (if no match)

    Args:
        value (str):
            observable value
    Returns:
        str: one of `ip`, `url`, `domain`, `hash` or 'generic'.
    """
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if re.match(
            r"^(?:ht|f)tps?://[a-z\d-]{1,63}(?:\.[a-z\d-]{1,63})+"
            r"(?:/[a-zA-Z\d-]{1,63})*(?:\.\w+)?",
            value,
        ):
            classification = ObservableTypes.URL
        elif re.match(
            r"^(\.)?[a-z\d-]{1,63}(\.[a-z\d-]{1,63})+$", value, re.IGNORECASE
        ):
            classification = ObservableTypes.DOMAIN
        elif (
            re.match(r"^[a-f\d]{32}$", value, re.IGNORECASE)
            or re.match(r"^[a-f\d]{40}$", value, re.IGNORECASE)
            or re.match(r"^[a-f\d]{64}$", value, re.IGNORECASE)
        ):
            classification = ObservableTypes.HASH
        else:
            classification = ObservableTypes.GENERIC
            logger.info(
                "Couldn't detect observable classification, setting as 'generic'..."
            )
    else:
        # it's a simple IP
        classification = ObservableTypes.IP

    return classification


def calculate_md5(value) -> str:
    return hashlib.md5(value).hexdigest()


def get_ip_version(ip_value):
    """
    Returns ip version
    Supports IPv4 and IPv6
    """
    ip_type = None
    try:
        ip = ipaddress.ip_address(ip_value)
        ip_type = ip.version
    except ValueError as e:
        logger.error(e)
    return ip_type


def get_hash_type(hash_value):
    """
    Returns hash type
    Supports md5, sha1, sha256 and sha512
    """
    RE_HASH_MAP = {
        "md5": re.compile(r"^[a-f\d]{32}$", re.IGNORECASE | re.ASCII),
        "sha-1": re.compile(r"^[a-f\d]{40}$", re.IGNORECASE | re.ASCII),
        "sha-256": re.compile(r"^[a-f\d]{64}$", re.IGNORECASE | re.ASCII),
        "sha-512": re.compile(r"^[a-f\d]{128}$", re.IGNORECASE | re.ASCII),
    }

    detected_hash_type = None
    for hash_type, re_hash in RE_HASH_MAP.items():
        if re.match(re_hash, hash_value):
            detected_hash_type = hash_type
            break
    return detected_hash_type  # stays None if no matches


def stack_analyzers(
    job_id: int,
    analyzers_to_execute: List[str],
    runtime_configuration: Dict[str, Dict] = None,
) -> Tuple[List[Signature], List[str]]:

    # to store the celery task signatures
    task_signatures = []
    analyzers_used = []

    analyzer_dataclasses = AnalyzerConfig.all()

    # get job
    job = Job.objects.get(pk=job_id)
    job.update_status(Job.Status.RUNNING)  # set job status to running

    # loop over and create task signatures
    for a_name in analyzers_to_execute:
        # get corresponding dataclass
        config = analyzer_dataclasses.get(a_name, None)
        if config is None:
            raise NotRunnableAnalyzer(
                        f"{a_name} won't run: not available in configuration"
            )

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
        ]
        # get celery queue
        queue = config.config.queue
        if queue not in settings.CELERY_QUEUES:
            logger.warning(
                f"Analyzer {a_name} has a wrong queue." f" Setting to `{DEFAULT_QUEUE}`"
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


def stack_connectors(
    job_id: int,
    connectors_to_execute: List[str],
    runtime_configuration: Dict[str, Dict] = None,
) -> Tuple[List[Signature], List[str]]:
    # to store the celery task signatures
    task_signatures = []

    connectors_used = []

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
        connectors_used.append(c_name)
    
    return task_signatures, connectors_used



def job_cleanup(job: Job) -> None:
    logger.info(f"[STARTING] job_cleanup for <-- {job.__repr__()}.")
    status_to_set = job.Status.RUNNING

    try:
        if job.status == job.Status.FAILED:
            raise AlreadyFailedJobException()

        stats = job.get_analyzer_reports_stats()

        logger.info(f"[REPORT] {job.__repr__()}, status:{job.status}, reports:{stats}")

        if len(job.analyzers_to_execute) == stats["all"]:
            if stats["running"] > 0 or stats["pending"] > 0:
                status_to_set = job.Status.RUNNING
            elif stats["success"] == stats["all"]:
                status_to_set = job.Status.REPORTED_WITHOUT_FAILS
            elif stats["failed"] == stats["all"]:
                status_to_set = job.Status.FAILED
            elif stats["failed"] >= 1 or stats["killed"] >= 1:
                status_to_set = job.Status.REPORTED_WITH_FAILS
            elif stats["killed"] == stats["all"]:
                status_to_set = job.Status.KILLED

    except AlreadyFailedJobException:
        logger.error(
            f"[REPORT] {job.__repr__()}, status: failed. Do not process the report"
        )

    except Exception as e:
        logger.exception(f"job_id: {job.pk}, Error: {e}")
        job.append_error(str(e), save=False)

    finally:
        if not (job.status == job.Status.FAILED and job.finished_analysis_time):
            job.finished_analysis_time = get_now()
        job.status = status_to_set
        job.save(update_fields=["status", "errors", "finished_analysis_time"])
