import logging
import traceback
import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general
from intel_owl import secrets

logger = logging.getLogger(__name__)

vt_base = "https://www.virustotal.com/vtapi/v2/"


def run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    logger.info("started analyzer {} job_id {} observable {}"
                "".format(analyzer_name, job_id, observable_name))
    report = general.get_basic_report_template(analyzer_name)
    try:
        api_key_name = additional_config_params.get('api_key_name', '')
        if not api_key_name:
            api_key_name = "VT_KEY"
        api_key = secrets.get_secret(api_key_name)
        if not api_key:
            raise AnalyzerRunException("no api key retrieved")

        result = vt_get_report(api_key, observable_name, observable_classification)

        # pprint.pprint(result)
        report['report'] = result
    except AnalyzerRunException as e:
        error_message = "job_id:{} analyzer:{} observable_name:{} Analyzer error {}" \
                        "".format(job_id, analyzer_name, observable_name, e)
        logger.error(error_message)
        report['errors'].append(error_message)
        report['success'] = False
    except Exception as e:
        traceback.print_exc()
        error_message = "job_id:{} analyzer:{} observable_name:{} Unexpected error {}" \
                        "".format(job_id, analyzer_name, observable_name, e)
        logger.exception(error_message)
        report['errors'].append(str(e))
        report['success'] = False
    else:
        report['success'] = True

    general.set_report_and_cleanup(job_id, report)

    logger.info("ended analyzer {} job_id {} observable {}"
                "".format(analyzer_name, job_id, observable_name))

    return report


def vt_get_report(api_key, observable_name, observable_classification):
    params = {'apikey': api_key}
    if observable_classification == 'domain':
        params['domain'] = observable_name
        uri = 'domain/report'
    elif observable_classification == 'ip':
        params['ip'] = observable_name
        uri = 'ip-address/report'
    elif observable_classification == 'url':
        params['resource'] = observable_name
        uri = 'url/report'
    elif observable_classification == 'hash':
        params['resource'] = observable_name
        params['allinfo'] = 1
        uri = 'file/report'
    else:
        raise AnalyzerRunException("not supported observable type {}. Supported are: hash, ip, domain and url"
                                   "".format(observable_classification))

    try:
        response = requests.get(vt_base + uri, params=params)
        response.raise_for_status()
    except requests.RequestException as e:
        raise AnalyzerRunException(e)
    result = response.json()
    response_code = result.get('response_code', 1)
    if response_code == -1:
        raise AnalyzerRunException("response code -1. result:{}".format(result))
    return result
