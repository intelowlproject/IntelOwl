import traceback
import logging
import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general
from intel_owl import secrets

logger = logging.getLogger(__name__)

base_url = 'https://api.securitytrails.com/v1/'

def run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    logger.info("started analyzer {} job_id {} observable {}"
                "".format(analyzer_name, job_id, observable_name))
    report = general.get_basic_report_template(analyzer_name)
    try:
        api_key_name = additional_config_params.get('api_key_name', '')
        if not api_key_name:
            api_key_name = "SECURITYTRAILS_KEY"
        api_key = secrets.get_secret(api_key_name)
        if not api_key:
            raise AnalyzerRunException("no api key retrieved")

        result = _securitytrails_get_report(api_key, observable_name, observable_classification,
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


def _securitytrails_get_report(api_key, observable_name, observable_classification, additional_config_params):
    securitytrails_analysis = additional_config_params.get('securitytrails_analysis', 'current')
    securitytrails_current_type = additional_config_params.get('securitytrails_current_type', 'details')
    securitytrails_history_analysis = additional_config_params.get('securitytrails_history_analysis', 'whois')

    headers = {
        'apikey': api_key,
        'Content-Type': 'application/json'
    }

    if observable_classification == 'ip':
        uri = 'ips/nearby/{}'.format(observable_name)
    elif observable_classification == 'domain':
        if securitytrails_analysis == 'current':
            if securitytrails_current_type == 'details':
                uri = 'domain/{}'.format(observable_name)
            elif securitytrails_current_type == 'subdomains':
                uri = 'domain/{}/subdomains'.format(observable_name)
            elif securitytrails_current_type == 'tags':
                uri = 'domain/{}/tags'.format(observable_name)
            else:
                raise AnalyzerRunException("not supported endpoint for current analysis.")

        elif securitytrails_analysis == 'history':
            if securitytrails_history_analysis == 'whois':
                uri = 'history/{}/whois'.format(observable_name)
            elif securitytrails_history_analysis == 'dns':
                    uri = 'history/{}/dns/a'.format(observable_name)
            else:
                raise AnalyzerRunException("not supported endpoint for current analysis.")

        else:
            raise AnalyzerRunException("not supported analysis type {}.".format(securitytrails_analysis))
    else:
        raise AnalyzerRunException("not supported observable type {}. Supported are ip and domain."
                                   "".format(observable_classification))

    try:
        response = requests.get(base_url + uri, headers = headers)
        response.raise_for_status()
    except requests.RequestException as e:
        raise AnalyzerRunException(e)
    result = response.json()
    return result
