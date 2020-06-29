import traceback

import requests
from celery.utils.log import get_task_logger

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general
from intel_owl import secrets

logger = get_task_logger(__name__)

base_url = "https://www.onyphe.io/api/v2/summary/"


def run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    logger.info(
        "started analyzer {} job_id {} observable {}"
        "".format(analyzer_name, job_id, observable_name)
    )
    report = general.get_basic_report_template(analyzer_name)
    try:
        api_key_name = additional_config_params.get("api_key_name", "ONYPHE_KEY")
        api_key = secrets.get_secret(api_key_name)
        if not api_key:
            raise AnalyzerRunException("no ONYPHE's API key retrieved")

        result = _onyphe_get_report(api_key, observable_name, observable_classification)

        report["report"] = result

    except AnalyzerRunException as e:
        error_message = (
            "job_id:{} analyzer:{} observable_name:{} Analyzer error {}"
            "".format(job_id, analyzer_name, observable_name, e)
        )
        logger.error(error_message)
        report["errors"].append(error_message)
        report["success"] = False
    except Exception as e:
        traceback.print_exc()
        error_message = (
            "job_id:{} analyzer:{} observable_name:{} Unexpected error {}"
            "".format(job_id, analyzer_name, observable_name, e)
        )
        logger.exception(error_message)
        report["errors"].append(str(e))
        report["success"] = False
    else:
        report["success"] = True

    general.set_report_and_cleanup(job_id, report)

    logger.info(
        "ended analyzer {} job_id {} observable {}"
        "".format(analyzer_name, job_id, observable_name)
    )

    return report


def _onyphe_get_report(api_key, observable_name, observable_classification):
    headers = {"Authorization": f"apikey {api_key}", "Content-Type": "application/json"}
    if observable_classification == "domain":
        uri = f"domain/{observable_name}"
    elif observable_classification == "ip":
        uri = f"ip/{observable_name}"
    elif observable_classification == "url":
        uri = f"hostname/{observable_name}"
    else:
        raise AnalyzerRunException(
            f"not supported observable type {observable_classification}."
            " Supported are: ip, domain and url."
        )

    try:
        response = requests.get(base_url + uri, headers=headers)
        response.raise_for_status()
    except requests.RequestException as e:
        raise AnalyzerRunException(e)
    result = response.json()
    return result
