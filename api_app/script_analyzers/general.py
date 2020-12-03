import logging
from celery.execute import send_task

from api_app.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from api_app.helpers import generate_sha256
from intel_owl.settings import CELERY_QUEUES
from .utils import (
    set_job_status,
    set_failed_analyzer,
    get_filepath_filename,
    get_observable_data,
    adjust_analyzer_config,
)

logger = logging.getLogger(__name__)


def start_analyzers(
    analyzers_to_execute,
    analyzers_config,
    runtime_configuration,
    job_id,
    md5,
    is_sample,
):
    set_job_status(job_id, "running")
    if is_sample:
        file_path, filename = get_filepath_filename(job_id)
    else:
        observable_name, observable_classification = get_observable_data(job_id)

    for analyzer in analyzers_to_execute:
        ac = analyzers_config[analyzer]
        try:
            module = ac.get("python_module", None)
            if not module:
                raise AnalyzerConfigurationException(
                    f"no python_module available in config for {analyzer} analyzer?!"
                )

            additional_config_params = ac.get("additional_config_params", {})

            adjust_analyzer_config(
                runtime_configuration, additional_config_params, analyzer
            )
            # get celery queue
            queue = ac.get("queue", "default")
            if queue not in CELERY_QUEUES:
                logger.error(
                    f"Analyzer {analyzers_to_execute} has a wrong queue."
                    f" Setting to default"
                )
                queue = "default"
            # construct arguments

            if is_sample:
                # check if we should run the hash instead of the binary
                run_hash = ac.get("run_hash", False)
                if run_hash:
                    # check which kind of hash the analyzer needs
                    run_hash_type = ac.get("run_hash_type", "md5")
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
                        f"observable_analyzers.{module}",
                        analyzer,
                        job_id,
                        hash_value,
                        "hash",
                        additional_config_params,
                    ]
                else:
                    # run the analyzer with the binary
                    args = [
                        f"file_analyzers.{module}",
                        analyzer,
                        job_id,
                        file_path,
                        filename,
                        md5,
                        additional_config_params,
                    ]
            else:
                # observables analyzer case
                args = [
                    f"observable_analyzers.{module}",
                    analyzer,
                    job_id,
                    observable_name,
                    observable_classification,
                    additional_config_params,
                ]
            # run analyzer with a celery task asynchronously
            stl = ac.get("soft_time_limit", 300)
            send_task(
                "run_analyzer",
                args=args,
                queue=queue,
                soft_time_limit=stl,
            )

        except (AnalyzerConfigurationException, AnalyzerRunException) as e:
            err_msg = f"({analyzer}, job_id #{job_id}) -> Error: {e}"
            logger.error(err_msg)
            set_failed_analyzer(analyzer, job_id, err_msg)
