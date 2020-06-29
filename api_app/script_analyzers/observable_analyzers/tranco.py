import requests
import traceback
import logging

from urllib.parse import urlparse

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general

logger = logging.getLogger(__name__)

base_url = "https://tranco-list.eu/api/ranks/domain/"


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
        observable_to_analyze = observable_name
        if observable_classification == "url":
            observable_to_analyze = urlparse(observable_name).hostname

        url = base_url + observable_to_analyze
        response = requests.get(url)
        response.raise_for_status()
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
