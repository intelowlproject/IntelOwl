# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import typing
from typing import Dict, List

from celery import chord
from django.utils.module_loading import import_string
from rest_framework.exceptions import ValidationError

from intel_owl import tasks
from intel_owl.celery import app as celery_app

from ..core.classes import Plugin
from ..models import Job
from .classes import DockerBasedAnalyzer
from .dataclasses import AnalyzerConfig
from .models import AnalyzerReport

logger = logging.getLogger(__name__)


def start_analyzers(
    job_id: int,
    analyzers_to_execute: List[str],
    runtime_configuration: Dict[str, Dict] = None,
) -> None:

    # we should not use mutable objects as default to avoid unexpected issues
    if runtime_configuration is None:
        runtime_configuration = {}

    cleaned_result = AnalyzerConfig.stack(
        job_id=job_id,
        plugins_to_execute=analyzers_to_execute,
        runtime_configuration=runtime_configuration,
    )

    task_signatures = cleaned_result[0]

    # fire the analyzers in a grouped celery task
    # also link the callback to be executed
    # canvas docs: https://docs.celeryproject.org/en/stable/userguide/canvas.html
    runner = chord(task_signatures)
    cb_signature = tasks.post_all_analyzers_finished.signature(
        [job_id, runtime_configuration], immutable=True
    )

    runner(cb_signature)

    return None


def set_failed_analyzer(
    job_id: int, name: str, err_msg, **report_defaults
) -> AnalyzerReport:
    status = AnalyzerReport.Status.FAILED
    logger.warning(
        f"(job: #{job_id}, analyzer:{name}) -> set as {status}. " f"Error: {err_msg}"
    )
    report, _ = AnalyzerReport.objects.get_or_create(
        job_id=job_id, name=name, defaults=report_defaults
    )
    report.status = status
    report.errors.append(err_msg)
    report.save()
    return report


def run_analyzer(
    job_id: int, config_dict: dict, report_defaults: dict, parent_playbook
) -> AnalyzerReport:
    aconfig = AnalyzerConfig.from_dict(config_dict)
    try:
        cls_path = aconfig.get_full_import_path()
        try:
            klass = import_string(cls_path)
        except ImportError:
            raise Exception(f"Class: {cls_path} couldn't be imported")
        # else
        instance = klass(config=aconfig, job_id=job_id, report_defaults=report_defaults)
        report = instance.start(parent_playbook=parent_playbook)
    except Exception as e:
        report = set_failed_analyzer(job_id, aconfig.name, str(e), **report_defaults)

    return report


def post_all_analyzers_finished(job_id: int, runtime_configuration: dict) -> None:
    """
    Callback fn that is executed after all analyzers have finished.
    """
    from intel_owl import tasks

    # get job instance
    job = Job.objects.get(pk=job_id)
    # execute some callbacks
    job.job_cleanup()
    # fire connectors when job finishes with success
    # avoid re-triggering of connectors (case: recurring analyzer run)
    if job.status == Job.Status.REPORTED_WITHOUT_FAILS and (
        len(job.connectors_to_execute) > 0 and job.connector_reports.count() == 0
    ):
        tasks.start_connectors.apply_async(
            args=[job_id, job.connectors_to_execute, runtime_configuration]
        )


def kill_ongoing_analysis(job: Job) -> None:
    """
    Terminates the analyzer tasks that are currently in running state.
    """
    statuses_to_filter = [
        AnalyzerReport.Status.PENDING,
        AnalyzerReport.Status.RUNNING,
    ]
    qs = job.analyzer_reports.filter(status__in=statuses_to_filter)
    # kill celery tasks using task ids
    task_ids = list(qs.values_list("task_id", flat=True))
    celery_app.control.revoke(task_ids, terminate=True)

    # update report statuses
    qs.update(status=AnalyzerReport.Status.KILLED)


def run_healthcheck(analyzer_name: str) -> bool:
    analyzer_config = AnalyzerConfig.get(analyzer_name)
    if analyzer_config is None:
        raise ValidationError({"detail": "Analyzer doesn't exist"})
    class_: typing.Type[Plugin] = analyzer_config.get_class()
    if not issubclass(class_, DockerBasedAnalyzer):
        raise ValidationError(f"Plugin {class_.__name__} is not docker based")

    # docker analyzers have a common method for health check
    if not hasattr(class_, "health_check"):
        raise ValidationError({"detail": "No healthcheck implemented"})

    return class_.health_check()
