import logging
import time
import requests

from api_app.exceptions import AnalyzerRunException
from api_app.helpers import get_binary
from api_app.script_analyzers.observable_analyzers import vt3_get
from api_app.script_analyzers.classes import FileAnalyzer
from intel_owl import secrets

logger = logging.getLogger(__name__)


vt_base = "https://www.virustotal.com/api/v3/"


class VirusTotalv3ScanFile(FileAnalyzer):
    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", "VT_KEY")
        self.__api_key = secrets.get_secret(self.api_key_name)
        self.additional_config_params = additional_config_params

    def run(self):
        if not self.__api_key:
            raise AnalyzerRunException(
                f"No API key retrieved with name: {self.api_key_name}"
            )

        return vt_scan_file(
            self.__api_key, self.md5, self.job_id, self.additional_config_params
        )


def vt_scan_file(api_key, md5, job_id, additional_config_params):
    try:
        binary = get_binary(job_id)
    except Exception:
        raise AnalyzerRunException("couldn't retrieve the binary to perform a scan")

    headers = {"x-apikey": api_key}
    files = {"file": binary}
    uri = "files"

    try:
        response = requests.post(vt_base + uri, files=files, headers=headers)
        response.raise_for_status()
    except requests.RequestException as e:
        raise AnalyzerRunException(e)
    result = response.json()

    result_data = result.get("data", {})
    scan_id = result_data.get("id", "")
    if not scan_id:
        raise AnalyzerRunException(
            "no scan_id given by VirusTotal to retrieve the results"
        )
    # max 5 minutes waiting
    max_tries = additional_config_params.get("max_tries", 100)
    poll_distance = 5
    got_result = False
    uri = f"analyses/{scan_id}"
    for chance in range(max_tries):
        time.sleep(poll_distance)
        logger.info(
            f"vt polling, try n.{chance + 1}. job_id {job_id}. starting the query"
        )
        try:
            response = requests.get(vt_base + uri, headers=headers)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)
        json_response = response.json()
        # pprint.pprint(json_response)
        analysis_status = (
            json_response.get("data", {}).get("attributes", {}).get("status", "")
        )
        if analysis_status == "completed":
            got_result = True
            break
        else:
            logger.info(
                "vt polling: try #{}. job_id: #{}. status:{}".format(
                    chance + 1, job_id, analysis_status
                )
            )

    if not got_result:
        raise AnalyzerRunException(
            f"max VT polls tried without getting any result. job_id {job_id}"
        )

    # retrieve the FULL report, not only scans results.
    # If it's a new sample, it's free of charge.
    return vt3_get.vt_get_report(api_key, md5, "hash", {}, job_id)
