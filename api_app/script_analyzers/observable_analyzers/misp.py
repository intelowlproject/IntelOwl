import datetime
import logging
import traceback

import pymisp

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
        api_key_name = additional_config_params.get("api_key_name", "")
        if not api_key_name:
            api_key_name = "MISP_KEY"
        api_key = secrets.get_secret(api_key_name)
        if not api_key:
            raise AnalyzerRunException(
                "no MISP API key retrieved, key value: {}".format(api_key_name)
            )

        url_key_name = additional_config_params.get("url_key_name", "")
        if not url_key_name:
            url_key_name = "MISP_URL"
        url_name = secrets.get_secret(url_key_name)
        if not url_name:
            raise AnalyzerRunException(
                "no MISP URL retrieved, key value: {}".format(url_key_name)
            )

        misp_instance = pymisp.ExpandedPyMISP(url_name, api_key)  # debug=True)

        # we check only for events not older than 90 days and max 50 results
        now = datetime.datetime.now()
        date_from = now - datetime.timedelta(days=90)
        params = {
            # even if docs say to use "values",...
            # .. at the moment it works correctly only with "value"
            "value": observable_name,
            "type_attribute": [observable_classification],
            "date_from": date_from.strftime("%Y-%m-%d %H:%M:%S"),
            "limit": 50,
            "enforce_warninglist": True,
        }
        if observable_classification == "hash":
            params["type_attribute"] = ["md5", "sha1", "sha256"]
        result_search = misp_instance.search(**params)
        if isinstance(result_search, dict):
            errors = result_search.get("errors", [])
            if errors:
                raise AnalyzerRunException(errors)
        report_to_give = {"result_search": result_search, "instance_url": url_name}
        report["report"] = report_to_give
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
    # pprint.pprint(report)

    logger.info(
        "ended analyzer {} job_id {} observable {}"
        "".format(analyzer_name, job_id, observable_name)
    )

    return report
