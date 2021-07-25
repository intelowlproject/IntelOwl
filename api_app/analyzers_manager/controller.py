# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import Dict, List
from celery import uuid
from django.core.cache import cache
from django.utils.module_loading import import_string
from django.conf import settings

from intel_owl.celery import app as celery_app

from .classes import BaseAnalyzerMixin
from .models import AnalyzerReport
from .serializers import AnalyzerConfigSerializer
from .dataclasses import AnalyzerConfig
from ..models import Job
from ..helpers import get_now
from ..exceptions import AlreadyFailedJobException, NotRunnableAnalyzer


logger = logging.getLogger(__name__)

# constants
CELERY_TASK_NAME = "run_analyzer"
ALL_ANALYZERS = "__all__"
DEFAULT_QUEUE = "default"


def build_cache_key(job_id: int) -> str:
    return f"job.{job_id}.analyzers_manager.task_ids"


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
) -> List[str]:
    # we should not use mutable objects as default to avoid unexpected issues
    if runtime_configuration is None:
        runtime_configuration = {}

    # mapping of analyzer name and task_id
    analyzers_task_id_map = {}

    # get analyzer config
    analyzer_dataclasses = AnalyzerConfigSerializer.get_as_dataclasses()

    # get job
    job = Job.objects.get(pk=job_id)
    job.update_status("running")  # set job status to running

    # loop over and fire the analyzers in a celery task
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
        # construct arguments
        args = [job_id, config.asdict()]
        kwargs = {"runtime_conf": runtime_conf}
        # get celery queue
        queue = config.params.queue
        if queue not in settings.CELERY_QUEUES:
            logger.warning(
                f"Analyzer {a_name} has a wrong queue." f" Setting to `{DEFAULT_QUEUE}`"
            )
            queue = DEFAULT_QUEUE
        # get soft_time_limit
        soft_time_limit = config.params.soft_time_limit
        # gen new task_id
        task_id = uuid()
        # add to map
        analyzers_task_id_map[a_name] = task_id
        # run analyzer with a celery task asynchronously
        celery_app.send_task(
            CELERY_TASK_NAME,
            args=args,
            kwargs=kwargs,
            queue=queue,
            soft_time_limit=soft_time_limit,
            task_id=task_id,
        )

    # cache the task ids
    cache.set(build_cache_key(job_id), analyzers_task_id_map)

    return analyzers_task_id_map


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


def set_failed_analyzer(job_id: int, analyzer_name: str, err_msg):
    status = AnalyzerReport.Statuses.FAILED.name
    logger.warning(
        f"(job: #{job_id}, analyzer:{analyzer_name}) -> set as {status}. ",
        f" Error: {err_msg}",
    )
    report, _ = AnalyzerReport.objects.get_or_create(
        job_id=job_id,
        analyzer_name=analyzer_name,
        report={},
        errors=[err_msg],
        status=status,
    )
    return report


def run_analyzer(job_id: int, config: AnalyzerConfig, **kwargs) -> AnalyzerReport:
    try:
        cls_path = config.get_full_import_path()
        try:
            klass: BaseAnalyzerMixin = import_string(cls_path)
        except ImportError:
            raise Exception(f"Class: {cls_path} couldn't be imported")

        instance = klass(config=config, job_id=job_id, **kwargs)
        report = instance.start()
    except Exception as e:
        report = set_failed_analyzer(job_id, config.name, str(e))

    return report
