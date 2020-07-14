import traceback

import requests
import logging

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general
from intel_owl import secrets

logger = logging.getLogger(__name__)


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
        api_version = additional_config_params.get("greynoise_api_version", "v1")
        if api_version == "v1":
            url = "https://api.greynoise.io/v1/query/ip"
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            data = {"ip": observable_name}

            response = requests.post(url, data=data, headers=headers)
            response.raise_for_status()
        elif api_version == "v2":
            url = f"https://api.greynoise.io/v2/noise/context/{observable_name}"
            api_key_name = additional_config_params.get(
                "api_key_name", "GREYNOISE_API_KEY"
            )
            api_key = secrets.get_secret(api_key_name)
            if not api_key:
                raise AnalyzerRunException("GREYNOISE_API_KEY not specified.")
            headers = {"Accept": "application/json", "key": api_key}
            response = requests.get(url, headers=headers)
            response.raise_for_status()
        else:
            raise AnalyzerRunException(
                "Invalid API Version. Supported are: v1 (free) & v2 (paid)."
            )

        result = response.json()
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
