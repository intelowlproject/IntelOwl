# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import typing
from typing import Dict, List

from celery import chord
from rest_framework.exceptions import ValidationError

from intel_owl import tasks

from ..core.classes import Plugin
from ..models import Job
from .classes import DockerBasedAnalyzer
from .dataclasses import AnalyzerConfig

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
