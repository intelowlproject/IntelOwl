# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import Dict, List, Tuple

from celery import chord, uuid
from celery.canvas import Signature
from django.conf import settings
from intel_owl import tasks
from django.utils.module_loading import import_string
from rest_framework.exceptions import ValidationError

from intel_owl.celery import app as celery_app
from intel_owl.consts import DEFAULT_QUEUE

from ..exceptions import AlreadyFailedJobException, NotRunnableAnalyzer
from ..helpers import get_now
from ..models import Job
from .classes import BaseAnalyzerMixin, DockerBasedAnalyzer
from .dataclasses import AnalyzerConfig
from .models import AnalyzerReport

logger = logging.getLogger(__name__)

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


def start_analyzers(
    job_id: int,
    analyzers_to_execute: List[str],
    runtime_configuration: Dict[str, Dict] = None,
) -> None:

    # we should not use mutable objects as default to avoid unexpected issues
    if runtime_configuration is None:
        runtime_configuration = {}
    
    cleaned_result = stack_analyzers(
        job_id=job_id,
        analyzers_to_execute=analyzers_to_execute,
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
    job_id: int, config_dict: dict, report_defaults: dict, parent_playbook=None
) -> AnalyzerReport:
    aconfig = AnalyzerConfig.from_dict(config_dict)
    klass: BaseAnalyzerMixin = None
    report: AnalyzerReport = None
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
    job_cleanup(job)
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
    cls_path = analyzer_config.get_full_import_path()

    try:
        klass: DockerBasedAnalyzer = import_string(cls_path)
    except ImportError:
        raise Exception(f"Class: {cls_path} couldn't be imported")

    # docker analyzers have a common method for health check
    if not hasattr(klass, "health_check"):
        raise ValidationError({"detail": "No healthcheck implemented"})

    return klass.health_check()
