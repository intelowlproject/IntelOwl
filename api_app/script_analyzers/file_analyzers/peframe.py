import requests
import traceback
import json
import logging
import time

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general

logger = logging.getLogger(__name__)


def run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    logger.info(f"started analyzer {analyzer_name} job_id {job_id}")
    report = general.get_basic_report_template(analyzer_name)
    try:
        # get binary
        binary = general.get_binary(job_id)
        # request new analysis
        req_data = {"args": ["-j", "@filetoscan"]}
        req_files = {"filetoscan": binary}
        r = requests.post("http://peframe:4000/peframe", files=req_files, data=req_data)
        r_data = r.json()
        if r.status_code in (200, 202):
            max_tries = additional_config_params.get("max_tries", 15)
            resp = _poll_for_result(job_id, r_data["key"], max_tries)
        else:
            raise AnalyzerRunException(r_data["error"])

        # limit the length of the strings dump
        result = resp.get("report", None)
        if result:
            result = json.loads(result)
            if "strings" in result and "dump" in result["strings"]:
                result["strings"]["dump"] = result["strings"]["dump"][:100]

        # set final report
        report["report"] = result
    except AnalyzerRunException as e:
        error_message = (
            f"job_id:{job_id} analyzer:{analyzer_name}"
            f" md5:{md5} filename:{filename} Analyzer Error: {e}"
        )
        logger.error(error_message)
        report["errors"].append(error_message)
        report["success"] = False
    except Exception as e:
        traceback.print_exc()
        error_message = (
            f"job_id:{job_id} analyzer:{analyzer_name} md5:{md5} filename:{filename}."
            f" Unexpected Error: {e}"
        )
        logger.exception(error_message)
        report["errors"].append(str(e))
        report["success"] = False
    else:
        report["success"] = True

    general.set_report_and_cleanup(job_id, report)

    logger.info(f"ended analyzer:{analyzer_name} job_id:{job_id}")

    return report


def _poll_for_result(job_id, hash, max_tries):
    poll_distance = 5
    got_result = False
    for chance in range(max_tries):
        time.sleep(poll_distance)
        logger.info(
            f"PEframe polling. Try n:{chance+1}, job_id:{job_id}. Starting the query"
        )
        try:
            status_code, json_data = _query_for_result(hash)
        except requests.RequestException as e:
            raise AnalyzerRunException(e)
        analysis_status = json_data.get("status", None)
        if analysis_status in ["success", "reported_with_fails", "failed"]:
            got_result = True
            break
        elif status_code == 404:
            pass
        else:
            logger.info(
                "PEframe polling."
                f" Try n:{chance+1}, job_id:{job_id}, status:{analysis_status}"
            )

    if got_result:
        return json_data
    else:
        raise AnalyzerRunException(
            f"max peframe polls tried without getting any result. job_id:{job_id}"
        )


def _query_for_result(key):
    headers = {"Accept": "application/json"}
    resp = requests.get(f"http://peframe:4000/peframe?key={key}", headers=headers)
    data = resp.json()
    return resp.status_code, data
