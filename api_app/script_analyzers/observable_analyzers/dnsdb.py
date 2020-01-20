import pprint
import json
import traceback
from urllib.parse import urlparse

import requests
from celery.utils.log import get_task_logger

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general
from intel_owl import secrets

logger = get_task_logger(__name__)


def run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    logger.info("started analyzer {} job_id {} observable {}"
                "".format(analyzer_name, job_id, observable_name))
    report = general.get_basic_report_template(analyzer_name)
    try:
        api_key_name = additional_config_params.get('api_key_name', '')
        if not api_key_name:
            api_key_name = "DNSDB_KEY"
        api_key = secrets.get_secret(api_key_name)
        if not api_key:
            raise AnalyzerRunException("no api key retrieved")

        limit = additional_config_params.get('limit', 1000)
        if not isinstance(limit, int):
            raise AnalyzerRunException("limit {} ({}) must be a integer".format(limit, type(limit)))

        headers = {
            'Accept': 'application/json',
            'X-API-Key': api_key
        }

        observable_to_check = observable_name
        # for URLs we are checking the relative domain
        if observable_classification == 'url':
            observable_to_check = urlparse(observable_name).hostname

        if observable_classification == 'ip':
            endpoint = "rdata/ip"
        elif observable_classification in ['domain', 'url']:
            endpoint = "rrset/name"
        else:
            raise AnalyzerRunException("{} not supported".format(observable_classification))

        url = 'https://api.dnsdb.info/lookup/{}/{}' \
              ''.format(endpoint, observable_to_check)
        params = {
            'limit': limit
        }
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()
        results_list = response.text
        json_extracted_results = []
        for item in results_list.split('\n'):
            if item:
                json_extracted_results.append(json.loads(item))

        # pprint.pprint(json_extracted_results)
        report['report'] = json_extracted_results
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

