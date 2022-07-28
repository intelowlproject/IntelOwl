import logging
from typing import Dict, List, Tuple
from celery import uuid
from django.conf import settings
from api_app.connectors_manager.dataclasses import ConnectorConfig
from api_app.helpers import get_now

from intel_owl import tasks
from api_app.analyzers_manager.dataclasses import AnalyzerConfig
from api_app.exceptions import AlreadyFailedJobException, NotRunnableAnalyzer
from api_app.models import Job
from intel_owl.consts import DEFAULT_QUEUE
from celery.canvas import Signature


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
