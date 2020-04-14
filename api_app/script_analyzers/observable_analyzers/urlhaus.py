import traceback

import requests
from celery.utils.log import get_task_logger

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general

logger = get_task_logger(__name__)

base_url = "https://urlhaus-api.abuse.ch/v1/"


def run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    logger.info("started analyzer {} job_id {} observable {}"
                "".format(analyzer_name, job_id, observable_name))
    report = general.get_basic_report_template(analyzer_name)
    try:
        result = _urlhaus_get_report(observable_name, observable_classification)
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


def _urlhaus_get_report(observable_name, observable_classification):
    headers = {
        'Accept': 'application/json'
    }
    if observable_classification == 'domain':
        uri = 'host/'
        post_data = {'host': observable_name}
    elif observable_classification == 'url':
        uri = 'url/'
        post_data = {'url': observable_name}
    else:
        raise AnalyzerRunException(f"not supported observable type {observable_classification}."
                                   f" Supported are: domain and url.")

    try:
        response = requests.post(base_url + uri, data=post_data, headers=headers)
        response.raise_for_status()
    except requests.RequestException as e:
        raise AnalyzerRunException(e)
    result = response.json()
    return result
