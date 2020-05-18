import traceback
import logging
import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general
from intel_owl import secrets

logger = logging.getLogger(__name__)

base_url = 'https://www.censys.io/api/v1'


def run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    logger.info("started analyzer {} job_id {} observable {}"
                "".format(analyzer_name, job_id, observable_name))
    report = general.get_basic_report_template(analyzer_name)
    try:
        api_id_name = additional_config_params.get('api_id_name', 'CENSYS_API_ID')
        api_secret_name = additional_config_params.get('api_secret_name', 'CENSYS_API_SECRET')
        api_id = secrets.get_secret(api_id_name)
        api_secret = secrets.get_secret(api_secret_name)
        if not (api_id and api_secret):
            raise AnalyzerRunException("no api credentials retrieved")

        result = _censys_get_report((api_id, api_secret), observable_name, observable_classification,
                                    additional_config_params)

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


def _censys_get_report(api_creds, observable_name, observable_classification, additional_config_params):
    censys_analysis = additional_config_params.get('censys_analysis', 'search')
    if censys_analysis == 'search':
        uri = '/view/ipv4/{}'.format(observable_name)
    else:
        raise AnalyzerRunException("not supported observable type {}. Supported is IP"
                                   "".format(observable_classification))        
    try:
        response = requests.get(base_url + uri, auth=api_creds)
        response.raise_for_status()
    except requests.RequestException as e:
        raise AnalyzerRunException(e)
    result = response.json()
    return result