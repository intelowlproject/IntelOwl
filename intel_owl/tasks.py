# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from __future__ import absolute_import, unicode_literals

import datetime
import logging
import typing

from celery import shared_task, signals
from celery.worker.consumer import Consumer
from celery.worker.control import control_command
from django.conf import settings
from django.db.models import Q
from django.utils.module_loading import import_string
from django.utils.timezone import now

from intel_owl import secrets
from intel_owl.celery import DEFAULT_QUEUE, app, get_queue_name

logger = logging.getLogger(__name__)


@control_command(
    args=[("plugin_path", str)],
)
def update_plugin(state, plugin_path):
    plugin = import_string(plugin_path)
    plugin.update()


@shared_task(soft_time_limit=10000)
def remove_old_jobs():
    """
    this is to remove old jobs to avoid to fill the database.
    Retention can be modified.
    """
    from api_app.models import Job

    logger.info("started remove_old_jobs")

    retention_days = int(secrets.get_secret("OLD_JOBS_RETENTION_DAYS", 14))
    date_to_check = now() - datetime.timedelta(days=retention_days)
    old_jobs = Job.objects.filter(finished_analysis_time__lt=date_to_check)
    num_jobs_to_delete = old_jobs.count()
    logger.info(f"found {num_jobs_to_delete} old jobs to delete")
    old_jobs.delete()

    logger.info("finished remove_old_jobs")
    return num_jobs_to_delete


@shared_task(soft_time_limit=120)
def check_stuck_analysis(minutes_ago: int = 25, check_pending: bool = False):
    """
    In case the analysis is stuck for whatever reason,
    we should force the status "failed"
    to avoid special exceptions,
    we can just put this function as a cron to cleanup.
    """
    from api_app.models import Job

    logger.info("started check_stuck_analysis")
    query = Q(status=Job.Status.RUNNING.value)
    if check_pending:
        query |= Q(status=Job.Status.PENDING.value)
    difference = now() - datetime.timedelta(minutes=minutes_ago)
    running_jobs = Job.objects.filter(query).filter(
        received_request_time__lte=difference
    )
    logger.info(f"checking if {running_jobs.count()} jobs are stuck")

    jobs_id_stuck = []
    for running_job in running_jobs:
        logger.error(
            f"found stuck analysis, job_id:{running_job.id}."
            f"Setting the job to status to {Job.Status.FAILED.value}'"
        )
        jobs_id_stuck.append(running_job.id)
        running_job.status = Job.Status.FAILED.value
        running_job.finished_analysis_time = now()
        running_job.process_time = running_job.calculate_process_time()
        running_job.save(
            update_fields=["status", "finished_analysis_time", "process_time"]
        )

    logger.info("finished check_stuck_analysis")

    return jobs_id_stuck


@shared_task(soft_time_limit=60)
def update(python_module: str, queue: str = None):
    from api_app.analyzers_manager.models import AnalyzerConfig
    from intel_owl.celery import broadcast

    analyzer_configs = AnalyzerConfig.objects.filter(python_module=python_module)
    if queue:
        analyzer_configs = analyzer_configs.filter(config__queue=queue)
    for analyzer_config in analyzer_configs:
        analyzer_config: AnalyzerConfig
        if analyzer_config.is_runnable():
            class_ = analyzer_config.python_class
            if hasattr(class_, "_update") and callable(class_._update):  # noqa
                if settings.NFS:
                    update_plugin(None, analyzer_config.python_complete_path)
                else:
                    broadcast(
                        update_plugin,
                        queue=analyzer_config.queue,
                        arguments={"plugin_path": analyzer_config.python_complete_path},
                    )
                return True
    logger.error(f"Unable to update {python_module}")
    return False


@shared_task(soft_time_limit=100)
def update_notifications_with_releases():
    from django.core import management

    management.call_command(
        "changelog_notification",
        ".github/CHANGELOG.md",
        "INTELOWL",
        "--number-of-releases",
        "1",
    )


@app.task(name="continue_job_pipeline", soft_time_limit=20)
def continue_job_pipeline(job_id: int):

    from api_app.models import Job

    job = Job.objects.get(pk=job_id)
    # execute some callbacks
    job.job_cleanup()


@app.task(name="job_pipeline", soft_time_limit=100)
def job_pipeline(
    job_id: int,
):
    from api_app.models import Job

    job = Job.objects.get(pk=job_id)
    job.execute()


@app.task(name="run_plugin", soft_time_limit=500)
def run_plugin(
    job_id: int,
    plugin_path: str,
    plugin_config_pk: str,
    runtime_configuration: dict,
    task_id: int,
):
    from api_app.core.classes import Plugin

    plugin_class: typing.Type[Plugin] = import_string(plugin_path)
    config = plugin_class.config_model.objects.get(pk=plugin_config_pk)
    plugin = plugin_class(
        config=config,
        job_id=job_id,
        runtime_configuration=runtime_configuration,
        task_id=task_id,
    )
    plugin.start()


# startup
@signals.worker_ready.connect
def worker_ready_connect(*args, sender: Consumer = None, **kwargs):

    logger.info(f"worker {sender.hostname} ready")
    queue = sender.hostname.split("_", maxsplit=1)[1]
    logger.info(f"Updating repositories inside {queue}")
    if settings.REPO_DOWNLOADER_ENABLED and queue == get_queue_name(DEFAULT_QUEUE):
        for python_module in [
            "maxmind.Maxmind",
            "talos.Talos",
            "tor.Tor",
            "yara_scan.YaraScan",
            "quark_engine.QuarkEngine",
            "phishing_army.PhishingArmy",
        ]:
            update(python_module, queue=queue)


# set logger
@signals.setup_logging.connect
def config_loggers(*args, **kwags):
    from logging.config import dictConfig

    dictConfig(settings.LOGGING)
