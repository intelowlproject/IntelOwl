import base64
import time
import traceback
import requests
import logging

from api_app.script_analyzers.file_analyzers import vt3_scan

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general
from intel_owl import secrets

logger = logging.getLogger(__name__)

vt_base = "https://www.virustotal.com/api/v3/"


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
            api_key_name = "VT_KEY"
        api_key = secrets.get_secret(api_key_name)
        if not api_key:
            raise AnalyzerRunException("no api key retrieved")

        result = vt_get_report(
            api_key,
            observable_name,
            observable_classification,
            additional_config_params,
            job_id,
        )

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

    # pprint.pprint(report)

    general.set_report_and_cleanup(job_id, report)

    logger.info(
        "ended analyzer {} job_id {} observable {}"
        "".format(analyzer_name, job_id, observable_name)
    )

    return report


def vt_get_report(
    api_key,
    observable_name,
    observable_classification,
    additional_config_params,
    job_id,
):
    headers = {"x-apikey": api_key}
    params = {}
    # in this way, you just retrieved metadata about relationships
    # if you like to get all the data about specific relationships,...
    # ..you should perform another query
    # check vt3 API docs for further info
    if observable_classification == "domain":
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
    elif observable_classification == "ip":
        relationships_requested = [
            "communicating_files",
            "downloaded_files",
            "historical_whois",
            "referrer_files",
            "resolutions",
            "urls",
        ]
        uri = f"ip_addresses/{observable_name}"
    elif observable_classification == "url":
        relationships_requested = [
            "downloaded_files",
            "analyses",
            "last_serving_ip_address",
            "redirecting_urls",
            "submissions",
        ]
        url_id = base64.urlsafe_b64encode(observable_name.encode()).decode().strip("=")
        uri = f"urls/{url_id}"
    elif observable_classification == "hash":
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
            "not supported observable type {}. Supported are: hash, ip, domain and url"
            "".format(observable_classification)
        )

    if relationships_requested:
        params["relationships"] = ",".join(relationships_requested)

    max_tries = additional_config_params.get("max_tries", 6)
    poll_distance = 30
    result = {}
    for chance in range(max_tries):
        try:
            logger.info(
                "trying VT/v3 GET n.{} for job_id {}, observable {}"
                "".format(chance + 1, job_id, observable_name)
            )
            response = requests.get(vt_base + uri, params=params, headers=headers)
            # this case is not a real error,...
            # .. it happens when a requested object is not found and that's normal
            if not response.status_code == 404:
                response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()

        if observable_classification == "hash":
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
                    result = vt3_scan.vt_scan_file(
                        api_key, observable_name, job_id, additional_config_params
                    )
                    result["performed_active_scan"] = True
                break
            else:
                # we should consider the chance that the very sample was already sent
                # and VT is already analyzing it.
                # In this case, just perform a little poll for the result
                last_analysis_results = (
                    result.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_results", {})
                )
                if last_analysis_results:
                    logger.info(f"hash {observable_name} found on VT with AV reports")
                    break
                else:
                    extra_polling_times = chance + 1
                    base_log = f"hash {observable_name} found on VT withOUT AV reports,"
                    if extra_polling_times == max_tries:
                        logger.info(f"{base_log} reached max tries: {max_tries}")
                    else:
                        logger.info(f"{base_log} performing another request...")
                        result["extra_polling_times"] = extra_polling_times
                        time.sleep(poll_distance)
        else:
            break

    return result
