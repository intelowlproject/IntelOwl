# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import Dict, List
from celery import uuid, signature, chord
from django.utils.module_loading import import_string
from django.conf import settings

from intel_owl.celery import app as celery_app

from .classes import BaseAnalyzerMixin
from .models import AnalyzerReport
from .serializers import AnalyzerConfigSerializer
from ..models import Job
from ..helpers import get_now
from ..exceptions import AlreadyFailedJobException, NotRunnableAnalyzer


logger = logging.getLogger(__name__)

# constants
ALL_ANALYZERS = "__all__"
DEFAULT_QUEUE = "default"


def filter_analyzers(serialized_data: Dict, warnings: List) -> List[str]:
    # init empty list
    cleaned_analyzer_list = []
    analyzers_requested = serialized_data["analyzers_requested"]

    # run all analyzers ?
    run_all = serialized_data.get("run_all_available_analyzers", False)

    # read config
    analyzer_dataclasses = AnalyzerConfigSerializer.get_as_dataclasses()
    all_analyzer_names: List[str] = list(analyzer_dataclasses.keys())
    if run_all:
        # select all
        selected_analyzers: List[str] = all_analyzer_names
    else:
        # select the ones requested
        selected_analyzers: List[str] = analyzers_requested

    for a_name in selected_analyzers:
        try:
            found = a_name not in all_analyzer_names
            if not run_all and found:
                raise NotRunnableAnalyzer(f"{a_name} not available in configuration")

            config = analyzer_dataclasses[a_name]

            if not config.is_ready_to_use:
                raise NotRunnableAnalyzer(
                    f"{a_name} is disabled or unconfigured, won't be run."
                )

            if serialized_data["is_sample"]:
                if not config.is_type_file:
                    raise NotRunnableAnalyzer(
                        f"{a_name} won't be run because does not support files."
                    )
                if not config.is_filetype_supported(serialized_data["file_mimetype"]):
                    raise NotRunnableAnalyzer(
                        f"{a_name} won't be run because mimetype "
                        f"{serialized_data['file_mimetype']} is not supported."
                    )
            else:
                if not config.is_type_observable:
                    raise NotRunnableAnalyzer(
                        f"{a_name} won't be run because does not support observable."
                    )

                if not config.is_observable_type_supported(
                    serialized_data["observable_classification"]
                ):
                    raise NotRunnableAnalyzer(
                        f"{a_name} won't be run because does not support observable  "
                        f"type {serialized_data['observable_classification']}."
                    )

            if serialized_data["force_privacy"] and config.leaks_info:
                raise NotRunnableAnalyzer(
                    f"{a_name} won't be run because it leaks info externally."
                )
            if (
                serialized_data["disable_external_analyzers"]
                and config.external_service
            ):
                raise NotRunnableAnalyzer(
                    f"{a_name} won't be run because you filtered external analyzers."
                )
        except NotRunnableAnalyzer as e:
            if run_all:
                # in this case, they are not warnings but expected and wanted behavior
                logger.debug(e)
            else:
                logger.warning(e)
                warnings.append(str(e))
        else:
            cleaned_analyzer_list.append(a_name)

    return cleaned_analyzer_list


def start_analyzers(
    job_id: int,
    analyzers_to_execute: List[str],
    runtime_configuration: Dict[str, Dict] = None,
) -> None:
    # we should not use mutable objects as default to avoid unexpected issues
    if runtime_configuration is None:
        runtime_configuration = {}

    # to store the celery task signatures
    task_signatures = []

    # get analyzer config
    analyzer_dataclasses = AnalyzerConfigSerializer.get_as_dataclasses()

    # get job
    job = Job.objects.get(pk=job_id)
    job.update_status("running")  # set job status to running

    # loop over and create task signatures
    for a_name in analyzers_to_execute:
        # get corresponding dataclass
        config = analyzer_dataclasses[a_name]

        # if disabled or unconfigured (this check is bypassed in TEST_MODE)
        if not config.is_ready_to_use and not settings.TEST_MODE:
            continue

        # get runtime_configuration if any specified for this analyzer
        runtime_conf = runtime_configuration.get(a_name, {})

        # merge runtime_conf
        config.config = {
            **config.config,
            **runtime_conf,
        }
        # gen new task_id
        task_id = uuid()
        # construct arguments
        args = [
            job_id,
            config.asdict(),
            {"runtime_configuration": runtime_conf, "task_id": task_id},
        ]
        # get celery queue
        queue = config.params.queue
        if queue not in settings.CELERY_QUEUES:
            logger.warning(
                f"Analyzer {a_name} has a wrong queue." f" Setting to `{DEFAULT_QUEUE}`"
            )
            queue = DEFAULT_QUEUE
        # get soft_time_limit
        soft_time_limit = config.params.soft_time_limit
        # create task signature and add to list
        task_signatures.append(
            signature(
                "run_analyzer",
                args=args,
                queue=queue,
                soft_time_limit=soft_time_limit,
                task_id=task_id,
            )
        )

    # fire the analyzers in a grouped celery task
    # also link the callback to be executed
    # canvas docs: https://docs.celeryproject.org/en/stable/userguide/canvas.html
    runner = chord(task_signatures)
    cb_signature = signature(
        "post_all_analyzers_finished", args=[job.pk], immutable=True
    )
    runner(cb_signature)

    return None


def job_cleanup(job: Job) -> None:
    logger.info(f"[STARTING] job_cleanup for <-- {job.__repr__()}.")
    status_to_set = "running"

    try:
        if job.status == "failed":
            raise AlreadyFailedJobException()

        stats = job.get_analyzer_reports_stats()

        logger.info(f"[REPORT] {job.__repr__()}, status:{job.status}, reports:{stats}")

        if len(job.analyzers_to_execute) == stats["all"]:
            if stats["running"] > 0 or stats["pending"] > 0:
                status_to_set = "running"
            elif stats["success"] == stats["all"]:
                status_to_set = "reported_without_fails"
            elif stats["failed"] == stats["all"]:
                status_to_set = "failed"
            elif stats["failed"] >= 1:
                status_to_set = "reported_with_fails"
            elif stats["killed"] == stats["all"]:
                status_to_set = "killed"

    except AlreadyFailedJobException:
        logger.error(
            f"[REPORT] {job.__repr__()}, status: failed. Do not process the report"
        )

    except Exception as e:
        logger.exception(f"job_id: {job.pk}, Error: {e}")
        job.append_error(str(e), save=False)

    finally:
        if not (job.status == "failed" and job.finished_analysis_time):
            job.finished_analysis_time = get_now()
        job.status = status_to_set
        job.save(update_fields=["status", "errors", "finished_analysis_time"])


def set_failed_analyzer(job_id: int, name: str, err_msg, **report_defaults):
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
    job_id: int, config_dict: dict, report_defaults: dict
) -> AnalyzerReport:
    config = AnalyzerConfigSerializer.dict_to_dataclass(config_dict)
    try:
        cls_path = config.get_full_import_path()
        try:
            klass: BaseAnalyzerMixin = import_string(cls_path)
        except ImportError:
            raise Exception(f"Class: {cls_path} couldn't be imported")

        instance = klass(config=config, job_id=job_id, report_defaults=report_defaults)
        report = instance.start()
    except Exception as e:
        report = set_failed_analyzer(job_id, config.name, str(e), **report_defaults)

    return report


def post_all_analyzers_finished(job_id: int):
    """
    Callback fn that is executed after all analyzers have finished.
    """
    # get job instance
    job = Job.objects.get(pk=job_id)
    # execute some callbacks
    job_cleanup(job)
    # fire connectors when job finishes with success
    # avoid re-triggering of connectors (case: recurring analyzer run)
    if job.status == "reported_without_fails" and not len(job.connectors_to_execute):
        signature("on_job_success", args=[job_id]).apply_async()


def kill_ongoing_analysis(job: Job):
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
