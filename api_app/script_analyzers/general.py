import logging

from api_app.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from api_app.helpers import generate_sha256
from .utils import (
    set_job_status,
    set_failed_analyzer,
    get_filepath_filename,
    get_observable_data,
)
from intel_owl import tasks, settings

logger = logging.getLogger(__name__)


def start_analyzers(analyzers_to_execute, analyzers_config, job_id, md5, is_sample):
    set_job_status(job_id, "running")
    if is_sample:
        file_path, filename = get_filepath_filename(job_id)
    else:
        observable_name, observable_classification = get_observable_data(job_id)

    for analyzer in analyzers_to_execute:
        try:
            analyzer_module = analyzers_config[analyzer].get("python_module", None)
            if not analyzer_module:
                message = (
                    f"no python_module available in config for {analyzer} analyzer?!"
                )
                raise AnalyzerConfigurationException(message)

            additional_config_params = analyzers_config[analyzer].get(
                "additional_config_params", {}
            )

            # run analyzer with a celery task asynchronously
            if is_sample:
                # check if we should run the hash instead of the binary
                run_hash = analyzers_config[analyzer].get("run_hash", False)
                if run_hash:
                    # check which kind of hash the analyzer needs
                    run_hash_type = analyzers_config[analyzer].get(
                        "run_hash_type", "md5"
                    )
                    if run_hash_type == "md5":
                        hash_value = md5
                    elif run_hash_type == "sha256":
                        hash_value = generate_sha256(job_id)
                    else:
                        error_message = (
                            f"only md5 and sha256 are supported "
                            f"but you asked {run_hash_type}. job_id: {job_id}"
                        )
                        raise AnalyzerConfigurationException(error_message)
                    # run the analyzer with the hash
                    args = [
                        analyzer,
                        job_id,
                        hash_value,
                        "hash",
                        additional_config_params,
                    ]
                    getattr(tasks, analyzer_module).apply_async(
                        args=args, queue=settings.CELERY_TASK_DEFAULT_QUEUE
                    )
                else:
                    # run the analyzer with the binary
                    args = [
                        analyzer,
                        job_id,
                        file_path,
                        filename,
                        md5,
                        additional_config_params,
                    ]
                    getattr(tasks, analyzer_module).apply_async(
                        args=args, queue=settings.CELERY_TASK_DEFAULT_QUEUE
                    )
            else:
                # observables analyzer case
                args = [
                    analyzer,
                    job_id,
                    observable_name,
                    observable_classification,
                    additional_config_params,
                ]
                getattr(tasks, analyzer_module).apply_async(
                    args=args, queue=settings.CELERY_TASK_DEFAULT_QUEUE
                )

        except (AnalyzerConfigurationException, AnalyzerRunException) as e:
            error_message = "job_id {}. analyzer: {}. error: {}".format(
                job_id, analyzer, e
            )
            logger.error(error_message)
            set_failed_analyzer(analyzer, job_id, error_message)
