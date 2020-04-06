"""Module to retrieve active DNS resolution
"""

import traceback
import requests
import ipaddress
import socket

from api_app.exceptions import AnalyzerConfigurationException, AnalyzerRunException
from api_app.script_analyzers import general

import logging
logger = logging.getLogger(__name__)


def run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    """Run ActiveDNS analyzer

    Admit:
    * additional_config_params[service]: google - Google DoH (DNS over HTTPS)
    * additional_config_params[service]: cloudflare - CloudFlare DoH (DNS over HTTPS)
    * additional_config_params[service]: classic - classic DNS query

    Google and CloudFlare return an IP (or NXDOMAIN) from a domain.
    Classic support also reverse lookup (domain from IP)

    :param analyzer_name: Analyzer configuration in analyzer_config.json
    :type analyzer_name: str
    :param job_id: job identifier
    :type job_id: str
    :param observable_name: analyzed observable
    :type observable_name: str
    :param observable_classification: observable classification (allow: ip or domain) ip only classic
    :type observable_classification: str
    :param additional_config_params: params service to select the service
    :type additional_config_params: dict
    :return: report: name: observable_name, resolution: ip,NXDOMAIN, ''
    :rtype: report: dict
    """
    logger.info(f"started analyzer {analyzer_name} job_id {job_id} observable {observable_name}")
    report = general.get_basic_report_template(analyzer_name)

    try:
        dns_type = additional_config_params.get('service', '')
        if dns_type == 'google':
            _doh_google(job_id, analyzer_name, observable_classification, observable_name, report)
        elif dns_type == 'cloudflare':
            _doh_cloudflare(job_id, analyzer_name, observable_classification, observable_name,
                            report)
        elif dns_type == 'classic':
            _classic_dns(job_id, analyzer_name, observable_classification, observable_name, report)
        else:
            raise AnalyzerConfigurationException(f'Service selected: {dns_type} is not available')

    except (AnalyzerConfigurationException, AnalyzerRunException) as e:
        error_message = f"job_id:{job_id} analyzer:{analyzer_name} " \
                        f"observable_name:{observable_name} Analyzer error {e}"
        logger.error(error_message)
        report['errors'].append(error_message)
        report['success'] = False
    except Exception as e:
        traceback.print_exc()
        error_message = f"job_id:{job_id} analyzer:{analyzer_name} " \
                        f"observable_name:{observable_name} Unexpected error {e}"
        logger.exception(error_message)
        report['errors'].append(str(e))
        report['success'] = False

    general.set_report_and_cleanup(job_id, report)

    logger.info(f"ended analyzer {analyzer_name} job_id {job_id} observable {observable_name}")

    return report


def _doh_google(job_id, analyzer_name, observable_classification, observable_name, report):
    if observable_classification == 'domain':
        try:
            response = requests.get('https://dns.google.com/resolve?name=' + observable_name)
            response.raise_for_status()
            data = response.json()
            ip = data.get("Answer", [{}])[0].get('data', 'NXDOMAIN')
            report['report'] = {'name': observable_name, 'resolution': ip}
            report['success'] = True
        except requests.exceptions.RequestException as error:
            error_message = f"job_id:{job_id}, analyzer:{analyzer_name}, " \
                            f"observable_classification:{observable_classification}, " \
                            f"observable_name:{observable_name}, RequestException {error}"
            logger.error(error_message)
            report['errors'].append(error_message)
            report['success'] = False
    else:
        error_message = f"job_id:{job_id}, analyzer:{analyzer_name}, " \
                        f"observable_classification:{observable_classification}, " \
                        f"observable_name:{observable_name}, " \
                        f"cannot analyze something different from domain"
        logger.error(error_message)
        report['errors'].append(error_message)
        report['success'] = False


def _doh_cloudflare(job_id, analyzer_name, observable_classification, observable_name, report):
    if observable_classification == 'domain':
        try:
            client = requests.session()
            params = {
                'name': observable_name,
                'type': 'A',
                'ct': 'application/dns-json',
            }
            response = client.get('https://cloudflare-dns.com/dns-query', params=params)
            response.raise_for_status()
            response_dict = response.json()
            response_answer = response_dict.get('Answer', [])
            # first resolution or NXDOMAIN if domain does not exist
            result_data = response_answer[0].get('data', 'NXDOMAIN') if response_answer else 'NXDOMAIN'
            report['report'] = {'name': observable_name, 'resolution': result_data}
            report['success'] = True
        except requests.exceptions.RequestException as error:
            error_message = f"job_id:{job_id}, analyzer:{analyzer_name}, " \
                            f"observable_classification:{observable_classification}, " \
                            f"observable_name:{observable_name}, RequestException {error}"
            logger.error(error_message)
            report['errors'].append(error_message)
            report['success'] = False
    else:
        error_message = f"job_id:{job_id}, analyzer:{analyzer_name}, " \
                        f"observable_classification:{observable_classification}, " \
                        f"observable_name:{observable_name}, " \
                        f"cannot analyze something different from domain"
        logger.error(error_message)
        report['errors'].append(error_message)
        report['success'] = False


def _classic_dns(job_id, analyzer_name, observable_classification, observable_name, report):
    result = {}
    if observable_classification == 'ip':
        ipaddress.ip_address(observable_name)
        try:
            domains = socket.gethostbyaddr(observable_name)
            # return a tuple (hostname, aliaslist, ipaddrlist), select hostname
            # if does not exist return socket.herror
            if domains:
                resolution = domains[0]
        except socket.herror:
            resolution = ''
        result = {'name': observable_name, 'resolution': resolution}
    elif observable_classification == 'domain':
        try:
            resolution = socket.gethostbyname(observable_name)
        except socket.gaierror:
            resolution = 'NXDOMAIN'
        result = {'name': observable_name, 'resolution': resolution}
    else:
        error_message = f"job_id:{job_id}, analyzer:{analyzer_name}, " \
                        f"observable_classification: {observable_classification}, " \
                        f"observable_name:{observable_name}, not analyzable"
        logger.error(error_message)
        report['errors'].append(error_message)
        report['success'] = False

    report['report'] = result
    report['success'] = True
