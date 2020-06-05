import json
import logging
import traceback
import requests

from urllib.parse import urlparse

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general

logger = logging.getLogger(__name__)

base_url = "https://freeapi.robtex.com/"


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
        robtex_analysis = additional_config_params.get("robtex_analysis", "ip_query")
        if robtex_analysis == "ip_query":
            uri = "ipquery/{}".format(observable_name)
        elif robtex_analysis == "reverse_pdns":
            uri = "pdns/reverse/{}".format(observable_name)
        elif robtex_analysis == "forward_pdns":
            domain = observable_name
            if observable_classification == "url":
                domain = urlparse(observable_name).hostname
            uri = "pdns/forward/{}".format(domain)
        else:
            raise AnalyzerRunException(
                "not supported analysis type {}.".format(robtex_analysis)
            )
        try:
            response = requests.get(base_url + uri)
            response.raise_for_status()
            result = response.text.split("\r\n")
        except requests.ConnectionError as e:
            raise AnalyzerRunException("connection error: {}".format(e))
        else:
            loaded_results = []
            for item in result:
                if len(item) > 0:
                    loaded_results.append(json.loads(item))

        # pprint.pprint(loaded_results)
        report["report"] = loaded_results
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
