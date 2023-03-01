# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import datetime
import logging

from intel_owl import secrets

from .helpers import get_now
from .models import Job

logger = logging.getLogger(__name__)


def check_stuck_analysis():
    """
    In case the analysis is stuck for whatever reason,
    we should force the status "failed"
    to avoid special exceptions,
    we can just put this function as a cron to cleanup.
    """
    logger.info("started check_stuck_analysis")
    running_jobs = list(Job.objects.filter(status="running"))
    logger.info(f"checking if {len(running_jobs)} jobs are stuck")

    now = get_now()
    difference = now - datetime.timedelta(minutes=25)
    jobs_id_stuck = []
    for running_job in running_jobs:
        if difference > running_job.received_request_time:
            logger.error(
                f"found stuck analysis, job_id:{running_job.id}."
                f"Setting the job to status to 'failed'"
            )
            jobs_id_stuck.append(running_job.id)
            running_job.status = "failed"
            running_job.finished_analysis_time = now
            running_job.process_time = running_job.calculate_process_time()
            running_job.save(
                update_fields=["status", "finished_analysis_time", "process_time"]
            )

    logger.info("finished check_stuck_analysis")

    return jobs_id_stuck


def remove_old_jobs():
    """
    this is to remove old jobs to avoid to fill the database.
    Retention can be modified.
    """
    logger.info("started remove_old_jobs")

    retention_days = secrets.get_secret("OLD_JOBS_RETENTION_DAYS")
    if not retention_days:
        retention_days = 3
    retention_days = int(retention_days)
    now = get_now()
    date_to_check = now - datetime.timedelta(days=retention_days)
    old_jobs = Job.objects.filter(finished_analysis_time__lt=date_to_check)
    num_jobs_to_delete = len(old_jobs)
    logger.info(f"found {num_jobs_to_delete} old jobs to delete")
    old_jobs.delete()

    logger.info("finished remove_old_jobs")
    return num_jobs_to_delete
