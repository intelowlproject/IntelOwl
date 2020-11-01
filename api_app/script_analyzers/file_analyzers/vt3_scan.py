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
        self.additional_config_params = additional_config_params
        # max no. of tries when polling for result
        self.max_tries = additional_config_params.get("max_tries", 100)
        # interval b/w HTTP requests when polling
        self.poll_distance = 5

    def run(self):
        api_key = secrets.get_secret(self.api_key_name)
        if not api_key:
            raise AnalyzerRunException(
                f"No API key retrieved with name: {self.api_key_name}"
            )

        return vt_scan_file(
            api_key,
            self.md5,
            self.job_id,
            max_tries=self.max_tries,
            poll_distance=self.poll_distance,
        )


def vt_scan_file(
    api_key,
    md5,
    job_id,
    rescan_instead=False,
    max_tries=100,
    poll_distance=5,
):
    try:
        binary = get_binary(job_id)
    except Exception:
        raise AnalyzerRunException("couldn't retrieve the binary to perform a scan")

    headers = {"x-apikey": api_key}
    if rescan_instead:
        logger.info(f"md5 {md5} job {job_id} VT analyzer requested rescan")
        files = {}
        uri = f"files/{md5}/analyse"
    else:
        logger.info(f"md5 {md5} job {job_id} VT analyzer requested scan")
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
                f"vt polling: try #{chance + 1}. job_id: #{job_id}."
                f" status:{analysis_status}"
            )

    if not got_result and not rescan_instead:
        raise AnalyzerRunException(
            f"max VT polls tried without getting any result. job_id {job_id}"
        )

    # retrieve the FULL report, not only scans results.
    # If it's a new sample, it's free of charge.
    return vt3_get.vt_get_report(api_key, md5, "hash", {}, job_id)
