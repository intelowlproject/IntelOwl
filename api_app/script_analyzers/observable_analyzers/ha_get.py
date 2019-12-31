import traceback

import requests
from celery.utils.log import get_task_logger

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general
from intel_owl import secrets

logger = get_task_logger(__name__)

ha_base = "https://www.hybrid-analysis.com/api/v2/"


def run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    logger.info("started analyzer {} job_id {} observable {}"
                "".format(analyzer_name, job_id, observable_name))
    report = general.get_basic_report_template(analyzer_name)
    try:
        api_key_name = additional_config_params.get('api_key_name', '')
        if not api_key_name:
            api_key_name = "HA_KEY"
        api_key = secrets.get_secret(api_key_name)
        if not api_key:
            raise AnalyzerRunException("no api key retrieved")

        result = _ha_get_report(api_key, observable_name, observable_classification)

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

    general.set_report_and_cleanup(job_id, report, logger)

    logger.info("ended analyzer {} job_id {} observable {}"
                "".format(analyzer_name, job_id, observable_name))

    return report


def _ha_get_report(api_key, observable_name, observable_classification):
    headers = {
        'api-key': api_key,
        'user-agent': 'Falcon Sandbox',
        'accept': 'application/json'
    }
    if observable_classification == 'domain':
        data = {'domain': observable_name}
        uri = 'search/terms'
    elif observable_classification == 'ip':
        data = {'host': observable_name}
        uri = 'search/terms'
    elif observable_classification == 'url':
        data = {'url': observable_name}
        uri = 'search/terms'
    elif observable_classification == 'hash':
        data = {'hash': observable_name}
        uri = 'search/hash'
    else:
        raise AnalyzerRunException("not supported observable type {}. Supported are: hash, ip, domain and url"
                                   "".format(observable_classification))

    try:
        response = requests.post(ha_base + uri, data=data, headers=headers)
        response.raise_for_status()
    except requests.RequestException as e:
        raise AnalyzerRunException(e)
    result = response.json()
    return result
