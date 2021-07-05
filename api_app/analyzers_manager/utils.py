# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from django.db import transaction

from api_app.models import Job
from api_app.helpers import get_now
from api_app.exceptions import AlreadyFailedJobException


logger = logging.getLogger(__name__)


def set_report_and_cleanup(analyzer_name, job_id):
    job_repr = f"({analyzer_name}, job_id: #{job_id})"
    logger.info(f"STARTING set_report_and_cleanup for <-- {job_repr}.")
    job_object = None

    try:
        with transaction.atomic():
            job_object = Job.object_by_job_id(job_id, transaction=True)
            job_object.save()
            if job_object.status == "failed":
                raise AlreadyFailedJobException()

        analysis_reports = job_object.analyzer_reports.all()
        num_analysis_reports = len(analysis_reports)
        num_analyzers_to_execute = len(job_object.analyzers_to_execute)
        logger.info(
            f"REPORT: num analysis reports:{num_analysis_reports}, "
            f"num analyzer to execute:{num_analyzers_to_execute}"
            f" <-- {job_repr}."
        )

        # check if it was the last analysis...
        # ..In case, set the analysis as "reported" or "failed"
        if num_analysis_reports == num_analyzers_to_execute:
            status_to_set = "reported_without_fails"
            # set status "failed" in case all analyzers failed
            failed_analyzers = 0
            for analysis_report in analysis_reports:
                if analysis_report.status != analysis_report.Statuses.SUCCESS.name:
                    failed_analyzers += 1

            if failed_analyzers == num_analysis_reports:
                status_to_set = "failed"
            elif failed_analyzers >= 1:
                status_to_set = "reported_with_fails"
            set_job_status(job_id, status_to_set)
            job_object.finished_analysis_time = get_now()
            job_object.save(update_fields=["finished_analysis_time"])

    except AlreadyFailedJobException:
        logger.error(f"job_id {job_id} status failed. Do not process the report")

    except Exception as e:
        logger.exception(f"job_id: {job_id}, Error: {e}")
        set_job_status(job_id, "failed", errors=[str(e)])
        job_object.finished_analysis_time = get_now()
        job_object.save(update_fields=["finished_analysis_time"])


def get_filepath_filename(job_id):
    # this function allows to minimize access to the database
    # in this way the analyzers could not touch the DB until the end of the analysis
    job_object = Job.object_by_job_id(job_id)
    filename = job_object.file_name
    file_path = job_object.file.path
    return file_path, filename


def get_observable_data(job_id):
    job_object = Job.object_by_job_id(job_id)
    observable_name = job_object.observable_name
    observable_classification = job_object.observable_classification
    return observable_name, observable_classification


def set_job_status(job_id, status, errors=None):
    message = f"setting job_id {job_id} to status {status}"
    if status == "failed":
        logger.error(message)
    else:
        logger.info(message)
    job_object = Job.object_by_job_id(job_id)
    if errors:
        job_object.errors.extend(errors)
    job_object.status = status
    job_object.save()


def set_failed_analyzer(analyzer_name, job_id, err_msg):
    logger.warning(
        f"({analyzer_name}, job_id #{job_id}) -> set as FAILED. "
        f" Error message: {err_msg}"
    )

    report = Job.init_report(analyzer_name, job_id)
    report.errors.append(err_msg)
    report.save()
    set_report_and_cleanup(analyzer_name, job_id)


def adjust_analyzer_config(
    runtime_conf, additional_config_params, analyzer, job_id, md5
):
    if runtime_conf:
        if analyzer in runtime_conf:
            analyzer_runtime_conf = runtime_conf[analyzer]
            additional_config_params.update(analyzer_runtime_conf)
            logger.info(
                f"job_id: {job_id} md5: {md5} adjusted analyzer"
                f" config for analyzer {analyzer}."
                f" New config: {additional_config_params}"
            )
