import json
import traceback
import requests

from celery.utils.log import get_task_logger
from urllib.parse import urlparse

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general


logger = get_task_logger(__name__)

base_url = "https://freeapi.robtex.com/"


def run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    logger.info("started analyzer {} job_id {} observable {}"
                "".format(analyzer_name, job_id, observable_name))
    report = general.get_basic_report_template(analyzer_name)
    try:
        result = _robtex_get_report(analyzer_name, observable_name, observable_classification)

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


def _robtex_get_report(analyzer_name, observable_name, observable_classification):

    if analyzer_name == 'Robtex_IP_Query':
        uri = 'ipquery/{}'.format(observable_name)
    elif analyzer_name == 'Robtex_Reverse_PDNS_Query':
        uri = 'pdns/reverse/{}'.format(observable_name)
    elif analyzer_name == 'Robtex_Forward_PDNS_Query':
        domain = observable_name
        if observable_classification == 'url':
            domain = urlparse(observable_name).hostname 
        uri = 'pdns/forward/{}'.format(domain)
    try:
        response = requests.get(base_url + uri)
        response.raise_for_status()
        result = response.text.split('\r\n')
    except requests.ConnectionError as e:
        raise AnalyzerRunException("connection error: {}".format(e))
    else:
        loaded_results = []
        for item in result:
            if len(item) > 0:
                loaded_results.append(json.loads(item))
    return loaded_results