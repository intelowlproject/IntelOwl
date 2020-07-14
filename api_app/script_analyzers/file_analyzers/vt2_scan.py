import time
import logging
import traceback

import requests
from api_app.script_analyzers import general

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers.observable_analyzers import vt2_get
from intel_owl import secrets

logger = logging.getLogger(__name__)

vt_base = "https://www.virustotal.com/vtapi/v2/"


def run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    logger.info(f"started analyzer: {analyzer_name} job_id: {job_id}")
    report = general.get_basic_report_template(analyzer_name)
    try:
        api_key_name = additional_config_params.get("api_key_name", "")
        if not api_key_name:
            api_key_name = "VT_KEY"
        api_key = secrets.get_secret(api_key_name)
        if not api_key:
            raise AnalyzerRunException("no api key retrieved")

        # this is a config value that can be used...
        # .. to force the waiting of the scan result anyway
        wait_for_scan_anyway = additional_config_params.get(
            "wait_for_scan_anyway", False
        )

        notify_url = secrets.get_secret("VT_NOTIFY_URL")

        binary = general.get_binary(job_id)
        result = _vt_scan_file(api_key, notify_url, binary)

        # in case we didn't use the webhook to get the result of the scan,...
        # .. start a poll for the result
        # or in case we'd like to force the scan anyway from the configuration
        if not notify_url or wait_for_scan_anyway:
            scan_id = result.get("scan_id", "")
            if not scan_id:
                raise (
                    AnalyzerRunException(
                        "no scan_id given by VirusTotal to retrieve the results"
                    )
                )
            # max 5 minutes waiting
            max_tries = additional_config_params.get("max_tries", 10)
            poll_distance = 30
            got_result = False
            for chance in range(max_tries):
                time.sleep(poll_distance)
                logger.info(f"vt polling, try n.{chance + 1}. job_id {job_id}")
                result = vt2_get.vt_get_report(api_key, scan_id, "hash")
                response_code = result.get("response_code", 1)
                # response code -2 means the we still have to wait
                if response_code == -2:
                    continue
                elif response_code == 1:
                    got_result = True
                    logger.info(
                        f"vt polling retrieved the result correctly for job_id {job_id}"
                    )
                    break
            if not got_result:
                logger.info(
                    f"max VT polls tried without getting any result. job_id {job_id}"
                )

        # pprint.pprint(result)
        report["report"] = result
    except AnalyzerRunException as e:
        error_message = (
            "job_id:{} analyzer:{} md5:{} filename: {} Analyzer Error {}"
            "".format(job_id, analyzer_name, md5, filename, e)
        )
        logger.error(error_message)
        report["errors"].append(error_message)
        report["success"] = False
    except Exception as e:
        traceback.print_exc()
        error_message = (
            "job_id:{} analyzer:{} md5:{} filename: {} Unexpected Error {}"
            "".format(job_id, analyzer_name, md5, filename, e)
        )
        logger.exception(error_message)
        report["errors"].append(str(e))
        report["success"] = False
    else:
        report["success"] = True

    general.set_report_and_cleanup(job_id, report)

    logger.info(f"ended analyzer: {analyzer_name} job_id: {job_id}")

    return report


def _vt_scan_file(api_key, notify_url, binary):
    params = {"apikey": api_key}
    if notify_url:
        params["notify_url"] = notify_url
    files = {"file": binary}
    uri = "file/scan"

    try:
        response = requests.post(vt_base + uri, files=files, params=params)
        response.raise_for_status()
    except requests.RequestException as e:
        raise AnalyzerRunException(e)
    result = response.json()
    response_code = result.get("response_code", 1)
    if response_code == -1:
        raise AnalyzerRunException("response code -1")
    return result
