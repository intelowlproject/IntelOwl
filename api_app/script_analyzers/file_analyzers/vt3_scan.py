import logging
import time
import traceback

import requests
from api_app.script_analyzers import general

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers.observable_analyzers import vt3_get
from intel_owl import secrets

logger = logging.getLogger(__name__)

vt_base = "https://www.virustotal.com/api/v3/"


def run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    logger.info("started analyzer {} job_id {}"
                "".format(analyzer_name, job_id))
    report = general.get_basic_report_template(analyzer_name)
    try:
        api_key_name = additional_config_params.get('api_key_name', '')
        if not api_key_name:
            api_key_name = "VT_KEY"
        api_key = secrets.get_secret(api_key_name)
        if not api_key:
            raise AnalyzerRunException("no api key retrieved")

        result = vt_scan_file(api_key, md5, job_id, additional_config_params)

        report['report'] = result
    except AnalyzerRunException as e:
        error_message = "job_id:{} analyzer:{} md5:{} filename: {} Analyzer Error {}" \
                        "".format(job_id, analyzer_name, md5, filename, e)
        logger.error(error_message)
        report['errors'].append(error_message)
        report['success'] = False
    except Exception as e:
        traceback.print_exc()
        error_message = "job_id:{} analyzer:{} md5:{} filename: {} Unexpected Error {}" \
                        "".format(job_id, analyzer_name, md5, filename, e)
        logger.exception(error_message)
        report['errors'].append(str(e))
        report['success'] = False
    else:
        report['success'] = True

    # pprint.pprint(report)

    general.set_report_and_cleanup(job_id, report)

    logger.info("ended analyzer {} job_id {}"
                "".format(analyzer_name, job_id))

    return report


def vt_scan_file(api_key, md5, job_id, additional_config_params):
    try:
        binary = general.get_binary(job_id)
    except Exception:
        raise AnalyzerRunException("couldn't retrieve the binary to perform a scan")

    headers = {'x-apikey': api_key}
    files = {'file': binary}
    uri = 'files'

    try:
        response = requests.post(vt_base + uri, files=files, headers=headers)
        response.raise_for_status()
    except requests.RequestException as e:
        raise AnalyzerRunException(e)
    result = response.json()
    # pprint.pprint(result)

    result_data = result.get('data', {})
    scan_id = result_data.get('id', '')
    if not scan_id:
        raise AnalyzerRunException("no scan_id given by VirusTotal to retrieve the results")
    # max 5 minutes waiting
    max_tries = additional_config_params.get('max_tries', 100)
    poll_distance = 5
    got_result = False
    uri = "analyses/{}".format(scan_id)
    for chance in range(max_tries):
        time.sleep(poll_distance)
        logger.info("vt polling, try n.{}. job_id {}. starting the query".format(chance+1, job_id))
        try:
            response = requests.get(vt_base + uri, headers=headers)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)
        json_response = response.json()
        # pprint.pprint(json_response)
        analysis_status = json_response.get('data', {}).get('attributes', {}).get('status', '')
        if analysis_status == "completed":
            got_result = True
            break
        else:
            logger.info("vt polling, try n.{}. job_id {}. status:{}".format(chance+1, job_id, analysis_status))

    if not got_result:
        raise AnalyzerRunException("max VT polls tried without getting any result. job_id {}".format(job_id))

    # retrieve the FULL report, not only scans results. If it's a new sample, it's free of charge
    result = vt3_get.vt_get_report(api_key, md5, "hash", {}, job_id)
    # pprint.pprint(result)
    return result
