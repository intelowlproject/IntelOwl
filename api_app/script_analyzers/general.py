import time
import logging
import hashlib

from api_app.exceptions import AnalyzerConfigurationException, AnalyzerRunException, AlreadyFailedJobException
from api_app.models import Job
from api_app.utilities import get_now
from intel_owl import tasks, settings

from django.utils import timezone

logger = logging.getLogger(__name__)


def start_analyzers(analyzers_to_execute, analyzers_config, job_id, md5, is_sample):
    set_job_status(job_id, "running")
    if is_sample:
        file_path, filename = get_filepath_filename(job_id)
    else:
        observable_name, observable_classification = get_observable_data(job_id)

    for analyzer in analyzers_to_execute:
        try:
            analyzer_module = analyzers_config[analyzer].get('python_module', '')
            if not analyzer_module:
                message = "no python_module available in config for {} analyzer?!".format(analyzer)
                raise AnalyzerConfigurationException(message)

            additional_config_params = analyzers_config[analyzer].get('additional_config_params', {})

            # run analyzer with a celery task asynchronously
            if is_sample:
                # check if we should run the hash instead of the binary
                run_hash = analyzers_config[analyzer].get('run_hash', '')
                if run_hash:
                    # check which kind of hash the analyzer needs
                    run_hash_type = analyzers_config[analyzer].get('run_hash_type', 'md5')
                    if run_hash_type == 'md5':
                        hash_value = md5
                    elif run_hash_type == 'sha256':
                        hash_value = generate_sha256(job_id)
                    else:
                        error_message = "only md5 and sha256 are supported but you asked {}. job_id {}" \
                                        "".format(run_hash_type, job_id)
                        raise AnalyzerConfigurationException(error_message)
                    # run the analyzer with the hash
                    args = [analyzer, job_id, hash_value, "hash", additional_config_params]
                    getattr(tasks, analyzer_module).apply_async(args=args, queue=settings.CELERY_TASK_DEFAULT_QUEUE)
                else:
                    # run the analyzer with the binary
                    args = [analyzer, job_id, file_path, filename, md5, additional_config_params]
                    getattr(tasks, analyzer_module).apply_async(args=args, queue=settings.CELERY_TASK_DEFAULT_QUEUE)
            else:
                # observables analyzer case
                args = [analyzer, job_id, observable_name, observable_classification, additional_config_params]
                getattr(tasks, analyzer_module).apply_async(args=args, queue=settings.CELERY_TASK_DEFAULT_QUEUE)

        except (AnalyzerConfigurationException, AnalyzerRunException) as e:
            error_message = "job_id {}. analyzer: {}. error: {}".format(job_id, analyzer, e)
            logger.error(error_message)
            set_failed_analyzer(analyzer, job_id, error_message)


def object_by_job_id(job_id):
    try:
        job_object = Job.objects.get(id=job_id)
    except Job.DoesNotExist:
        raise AnalyzerRunException("no job_id {} retrieved".format(job_id))

    return job_object


def get_binary(job_id, job_object=None):
    if not job_object:
        job_object = object_by_job_id(job_id)
    logger.info("getting binary for job_id {}".format(job_id))
    job_file = job_object.file
    logger.info("got job_file {} for job_id {}".format(job_file, job_id))

    binary = job_file.read()
    return binary


def generate_sha256(job_id):
    binary = get_binary(job_id)
    return hashlib.sha256(binary).hexdigest()


def get_filepath_filename(job_id):
    # this function allows to minimize access to the database
    # in this way the analyzers could not touch the DB until the end of the analysis
    job_object = object_by_job_id(job_id)

    filename = job_object.file_name

    file_path = job_object.file.path

    return file_path, filename


def get_observable_data(job_id):
    job_object = object_by_job_id(job_id)

    observable_name = job_object.observable_name
    observable_classification = job_object.observable_classification

    return observable_name, observable_classification


def get_basic_report_template(analyzer_name):
    return {
        "name": analyzer_name,
        "success": False,
        "report": {},
        "errors": [],
        "process_time": 0,
        "started_time": time.time(),
        "started_time_str": timezone.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def set_report_and_cleanup(job_id, report):
    logger.info("start set_report_and_cleanup for job_id:{}, analyzer:{}"
                "".format(job_id, report.get('name', '')))
    job_object = None

    try:
        job_object = object_by_job_id(job_id)
        if job_object.status == 'failed':
            raise AlreadyFailedJobException()

        # add process time
        finished_time = time.time()
        report['process_time'] = finished_time - report['started_time']

        job_object.analysis_reports.append(report)
        job_object.save(update_fields=['analysis_reports'])

        num_analysis_reports = len(job_object.analysis_reports)
        num_analyzers_to_execute = len(job_object.analyzers_to_execute)
        logger.info("job_id:{} num analysis reports:{} num analyzer to execute:{}"
                    "".format(job_id, num_analysis_reports, num_analyzers_to_execute))

        # check if it was the last analysis. In case, set the analysis as "reported" or "failed"
        if num_analysis_reports == num_analyzers_to_execute:
            status_to_set = "reported_without_fails"
            # set status "failed" in case all analyzers failed
            failed_analyzers = 0
            for analysis_report in job_object.analysis_reports:
                if not analysis_report.get('success', False):
                    failed_analyzers += 1
            if failed_analyzers == num_analysis_reports:
                status_to_set = "failed"
            elif failed_analyzers >= 1:
                status_to_set = "reported_with_fails"
            set_job_status(job_id, status_to_set)
            job_object.finished_analysis_time = get_now()
            job_object.save(update_fields=['finished_analysis_time'])

    except AlreadyFailedJobException:
        logger.error("job_id {} status failed. Do not process the report {}"
                     "".format(job_id, report))

    except Exception as e:
        logger.exception("job_id: {}, Error: {}".format(job_id, e))
        set_job_status(job_id, "failed", errors=[str(e)])
        job_object.finished_analysis_time = get_now()
        job_object.save(update_fields=['finished_analysis_time'])


def set_job_status(job_id, status, errors=None):
    message = "setting job_id {} to status {}".format(job_id, status)
    if status == 'failed':
        logger.error(message)
    else:
        logger.info(message)
    job_object = object_by_job_id(job_id)
    if errors:
        job_object.errors.extend(errors)
    job_object.status = status
    job_object.save()


def set_failed_analyzer(analyzer_name, job_id, error_message):
    logger.info("setting analyzer {} of job_id {} as failed. Error message:{}"
                "".format(analyzer_name, job_id, error_message))
    report = get_basic_report_template(analyzer_name)
    report['errors'].append(error_message)
    set_report_and_cleanup(job_id, report)


