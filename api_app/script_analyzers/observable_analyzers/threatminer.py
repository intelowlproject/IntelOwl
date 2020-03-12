import traceback

import requests
from celery.utils.log import get_task_logger

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general

logger = get_task_logger(__name__)

base_url = "https://api.threatminer.org/v2/"


def run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    logger.info("started analyzer {} job_id {} observable {}"
                "".format(analyzer_name, job_id, observable_name))
    report = general.get_basic_report_template(analyzer_name)
    try:
        rt_value = additional_config_params.get('rt_value', '')
        if not rt_value:
            rt_value = 1
        result = tm_get_report(rt_value, observable_name, observable_classification)

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


def tm_get_report(rt_value, observable_name, observable_classification):
    if observable_classification == 'domain':
        uri = 'domain.php'
    elif observable_classification == 'ip':
        uri = 'host.php'
    elif observable_classification == 'hash':
        uri = 'sample.php'
    else:
        raise AnalyzerRunException("not supported observable type {}. Supported are: hash, ip, domain and url"
                                   "".format(observable_classification))

    try:
        params = {
            'q': observable_name,
            'rt': rt_value       
        }
        response = requests.post(base_url + uri,params=params)
        response.raise_for_status()
    except requests.RequestException as e:
        raise AnalyzerRunException(e)
    result = response.json()
    return result