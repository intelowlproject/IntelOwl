import base64
import time
import requests
import logging

from datetime import datetime, timedelta

from api_app.script_analyzers.file_analyzers import vt3_scan
from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import secrets

logger = logging.getLogger(__name__)

vt_base = "https://www.virustotal.com/api/v3/"


class VirusTotalv3(classes.ObservableAnalyzer):
    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", "VT_KEY")
        self.__api_key = secrets.get_secret(self.api_key_name)
        self.additional_config_params = additional_config_params

    def run(self):
        if not self.__api_key:
            raise AnalyzerRunException(
                f"No API key retrieved with name: {self.api_key_name}"
            )

        result = vt_get_report(
            self.__api_key,
            self.observable_name,
            self.observable_classification,
            self.additional_config_params,
            self.job_id,
        )

        return result


def vt_get_report(
    api_key,
    observable_name,
    obs_clfn,
    additional_config_params,
    job_id,
):
    headers = {"x-apikey": api_key}

    params, uri = get_requests_params_and_uri(obs_clfn, observable_name)

    max_tries = additional_config_params.get("max_tries", 10)
    poll_distance = 30
    result = {}
    already_done_active_scan_because_report_was_old = False
    for chance in range(max_tries):
        try:
            logger.info(
                f"trying VT/v3 GET n.{chance + 1} for job_id {job_id}, "
                f"observable {observable_name}"
            )
            response = requests.get(vt_base + uri, params=params, headers=headers)
            # this case is not a real error,...
            # .. it happens when a requested object is not found and that's normal
            if not response.status_code == 404:
                response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()

        if obs_clfn == "hash":
            # this is an option to force active scan...
            # .. in the case the file is not in the VT DB
            # you need the binary too for this case, ..
            # .. otherwise it would fail if it's not available
            if response.status_code == 404:
                logger.info(f"hash {observable_name} not found on VT")
                force_active_file_scan = additional_config_params.get(
                    "force_active_scan", False
                )
                if force_active_file_scan:
                    logger.info(f"forcing VT active scan for hash {observable_name}")
                    result = vt3_scan.vt_scan_file(api_key, observable_name, job_id)
                    result["performed_active_scan"] = True
                break
            else:
                # we should consider the chance that the very sample was already...
                # ...sent and VT is already analyzing it.
                # In this case, just perform a little poll for the result
                attributes = result.get("data", {}).get("attributes", {})
                last_analysis_results = attributes.get("last_analysis_results", {})
                if last_analysis_results:
                    # at this time, if the flag if set,
                    # we are going to force the analysis again for old samples
                    force_active_file_scan_if_old = additional_config_params.get(
                        "force_active_scan_if_old", False
                    )
                    if (
                        force_active_file_scan_if_old
                        and not already_done_active_scan_because_report_was_old
                    ):
                        now = datetime.utcnow()
                        scan_date = attributes.get("last_analysis_date", 0)
                        scan_date_time = datetime.fromtimestamp(scan_date)
                        thirty_days_ago = now - timedelta(days=30)
                        if thirty_days_ago > scan_date_time:
                            logger.info(
                                f"hash {observable_name} found on VT with AV reports"
                                f" and scan is older than 30 days.\n"
                                f"We will force the analysis again"
                            )
                            # the "rescan" option will burn quotas.
                            # We should reduce the polling at the minimum
                            result = vt3_scan.vt_scan_file(
                                api_key,
                                observable_name,
                                job_id,
                                rescan_instead=True,
                                max_tries=2,
                                poll_distance=120,
                            )
                            already_done_active_scan_because_report_was_old = True
                        else:
                            logger.info(
                                f"hash {observable_name} found on VT"
                                f" with AV reports and scan is recent"
                            )
                            break
                    else:
                        logger.info(
                            f"hash {observable_name} found on VT with AV reports"
                        )
                        break
                else:
                    extra_polling_times = chance + 1
                    base_log = f"hash {observable_name} found on VT withOUT AV reports,"
                    if extra_polling_times == max_tries:
                        logger.warning(f"{base_log} reached max tries: {max_tries}")
                        result["reached_max_tries_and_no_av_report"] = True
                    else:
                        logger.info(f"{base_log} performing another request...")
                        result["extra_polling_times"] = extra_polling_times
                        time.sleep(poll_distance)
        else:
            break

    if already_done_active_scan_because_report_was_old:
        result["performed_rescan_because_report_was_old"] = True

    return result


def get_requests_params_and_uri(obs_clfn, observable_name):
    params = {}
    # in this way, you just retrieved metadata about relationships
    # if you like to get all the data about specific relationships,...
    # ..you should perform another query
    # check vt3 API docs for further info
    if obs_clfn == "domain":
        relationships_requested = [
            "communicating_files",
            "downloaded_files",
            "historical_whois",
            "referrer_files",
            "resolutions",
            "siblings",
            "subdomains",
            "urls",
        ]
        uri = f"domains/{observable_name}"
    elif obs_clfn == "ip":
        relationships_requested = [
            "communicating_files",
            "downloaded_files",
            "historical_whois",
            "referrer_files",
            "resolutions",
            "urls",
        ]
        uri = f"ip_addresses/{observable_name}"
    elif obs_clfn == "url":
        relationships_requested = [
            "downloaded_files",
            "analyses",
            "last_serving_ip_address",
            "redirecting_urls",
            "submissions",
        ]
        url_id = base64.urlsafe_b64encode(observable_name.encode()).decode().strip("=")
        uri = f"urls/{url_id}"
    elif obs_clfn == "hash":
        relationships_requested = [
            "behaviours",
            "bundled_files",
            "comments",
            "compressed_parents",
            "contacted_domains",
            "contacted_ips",
            "contacted_urls",
            "execution_parents",
            "itw_urls",
            "overlay_parents",
            "pcap_parents",
            "pe_resource_parents",
            "votes",
        ]
        uri = f"files/{observable_name}"
    else:
        raise AnalyzerRunException(
            f"Not supported observable type {obs_clfn}. "
            "Supported are: hash, ip, domain and url."
        )

    if relationships_requested:
        params["relationships"] = ",".join(relationships_requested)

    return params, uri
