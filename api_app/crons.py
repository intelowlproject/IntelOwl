import datetime
import logging

from api_app.models import Job
from api_app.script_analyzers import general
from api_app.utilities import get_now

logger = logging.getLogger(__name__)


def check_stuck_analysis():
    # in case the analysis is stuck for whatever, we should force the status "failed"
    # to avoid special exceptions, we can just put this function as a cron to cleanup
    logger.info("started check_stuck_analysis")
    running_jobs = Job.objects.filter(status="running")
    logger.info("checking if {} jobs are stuck".format(len(running_jobs)))

    jobs_id_stuck = []
    for running_job in running_jobs:
        now = get_now()
        difference = now - datetime.timedelta(minutes=25)
        if difference > running_job.received_request_time:
            logger.error("found stuck analysis, job_id:{}. Setting the job to status 'failed'".format(running_job.id))
            jobs_id_stuck.append(running_job.id)
            general.set_job_status(running_job.id, "failed", logger)
            running_job.finished_analysis_time = get_now()
            running_job.save(update_fields=['finished_analysis_time'])

    logger.info("finished check_stuck_analysis")

    return jobs_id_stuck


def remove_old_jobs():
    # this is to remove old jobs to avoid to fill the database. Retention can be modified.
    logger.info("started remove_old_jobs")

    retention_days = 3
    now = get_now()
    date_to_check = now - datetime.timedelta(days=retention_days)
    old_jobs = Job.objects.filter(finished_analysis_time__lt=date_to_check)
    num_jobs_to_delete = len(old_jobs)
    logger.info("found {} old jobs to delete".format(num_jobs_to_delete))
    old_jobs.delete()

    logger.info("finished remove_old_jobs")
    return num_jobs_to_delete
