import traceback
import logging
import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general
from intel_owl import secrets

logger = logging.getLogger(__name__)

base_url = "https://api.shodan.io/"


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
        api_key_name = additional_config_params.get("api_key_name", "")
        if not api_key_name:
            api_key_name = "SHODAN_KEY"
        api_key = secrets.get_secret(api_key_name)
        if not api_key:
            raise AnalyzerRunException("no api key retrieved")

        result = _shodan_get_report(
            api_key,
            observable_name,
            observable_classification,
            additional_config_params,
        )

        # pprint.pprint(result)
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


def _shodan_get_report(
    api_key, observable_name, observable_classification, additional_config_params
):
    shodan_analysis = additional_config_params.get("shodan_analysis", "search")

    if shodan_analysis == "search":
        params = {"key": api_key, "minify": True}
        uri = "shodan/host/{}".format(observable_name)
    elif shodan_analysis == "honeyscore":
        params = {
            "key": api_key,
        }
        uri = "labs/honeyscore/{}".format(observable_name)
    else:
        raise AnalyzerRunException(
            "not supported observable type {}. Supported is IP"
            "".format(observable_classification)
        )

    try:
        response = requests.get(base_url + uri, params=params)
        response.raise_for_status()
    except requests.RequestException as e:
        raise AnalyzerRunException(e)
    result = response.json()
    return result
