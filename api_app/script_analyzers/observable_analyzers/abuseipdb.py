import traceback
import logging

import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general
from intel_owl import secrets

logger = logging.getLogger(__name__)


def run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    logger.info("started analyzer {} job_id {} observable {}"
                "".format(analyzer_name, job_id, observable_name))
    report = general.get_basic_report_template(analyzer_name)
    try:
        api_key_name = additional_config_params.get('api_key_name', '')
        if not api_key_name:
            api_key_name = "ABUSEIPDB_KEY"
        api_key = secrets.get_secret(api_key_name)
        if not api_key:
            raise AnalyzerRunException("no api key retrieved")

        headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': observable_name,
            'maxAgeInDays': 180,
            'verbose': True
        }
        url = 'https://api.abuseipdb.com/api/v2/check'
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()

        json_response = response.json()
        # pprint.pprint(json_response)
        report['report'] = json_response
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

