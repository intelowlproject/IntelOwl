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


def run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    """Run ActiveDNS analyzer

    Admit:
    * additional_config_params[service]: google - Google DoH (DNS over HTTPS)
    * additional_config_params[service]: cloudflare - CloudFlare DoH (DNS over HTTPS)
    * additional_config_params[service]: cloudflare_malware -
        CloudFlare DoH (DNS over HTTPS) with Malware filtering
    * additional_config_params[service]: classic - classic DNS query

    Google and CloudFlare return an IP (or NXDOMAIN) from a domain.
    Classic support also reverse lookup (domain from IP)

    :param analyzer_name: str
        Analyzer configuration in analyzer_config.json
    :param job_id: str
        job identifier
    :param observable_name: str
        analyzed observable
    :param observable_classification: str
        observable classification (allow: ip or domain) ip only classic
    :param additional_config_params: dict
        params service to select the service
    :return: report: dict
        name: observable_name, resolution: ip,NXDOMAIN, ''
    """
    logger.info(
        f"started analyzer {analyzer_name} job_id {job_id} observable {observable_name}"
    )
    report = general.get_basic_report_template(analyzer_name)

    try:
        dns_type = additional_config_params.get("service", "")
        if dns_type == "google":
            _doh_google(
                job_id,
                analyzer_name,
                observable_classification,
                observable_name,
                report,
            )
        elif dns_type == "cloudflare":
            _doh_cloudflare(
                job_id,
                analyzer_name,
                observable_classification,
                observable_name,
                report,
            )
        elif dns_type == "cloudflare_malware":
            _doh_cloudflare_malware(
                job_id,
                analyzer_name,
                observable_classification,
                observable_name,
                report,
            )
        elif dns_type == "classic":
            _classic_dns(
                job_id,
                analyzer_name,
                observable_classification,
                observable_name,
                report,
            )
        else:
            raise AnalyzerConfigurationException(
                f"Service selected: {dns_type} is not available"
            )

    except (AnalyzerConfigurationException, AnalyzerRunException) as e:
        error_message = (
            f"job_id:{job_id} analyzer:{analyzer_name} "
            f"observable_name:{observable_name} Analyzer error {e}"
        )
        logger.error(error_message)
        report["errors"].append(error_message)
        report["success"] = False
    except Exception as e:
        traceback.print_exc()
        error_message = (
            f"job_id:{job_id} analyzer:{analyzer_name} "
            f"observable_name:{observable_name} Unexpected error {e}"
        )
        logger.exception(error_message)
        report["errors"].append(str(e))
        report["success"] = False
    else:
        report["success"] = True

    general.set_report_and_cleanup(job_id, report)

    logger.info(
        f"ended analyzer {analyzer_name} job_id {job_id} observable {observable_name}"
    )

    return report


def _doh_google(
    job_id, analyzer_name, observable_classification, observable_name, report
):
    if observable_classification == "domain":
        try:
            authority_answer = ""
            params = {
                "name": observable_name,
                # this filter should work but it is not
                "type": 1,
            }
            response = requests.get("https://dns.google.com/resolve", params=params)
            response.raise_for_status()
            data = response.json()
            ip = ""
            answers = data.get("Answer", [])
            for answer in answers:
                if answer.get("type", 1) == 1:
                    ip = answer.get("data", "NXDOMAIN")
                    break
            if not ip:
                authority = data.get("Authority", [])
                if authority:
                    authority_answer = authority[0].get("data", "")
                else:
                    logger.error(
                        f"observable: {observable_name} active_dns query"
                        f" retrieved no valid A answer: {answers}"
                    )
            report["report"] = {
                "name": observable_name,
                "resolution": ip,
                "authoritative_answer": authority_answer,
            }
        except requests.exceptions.RequestException as error:
            error_message = (
                f"job_id:{job_id}, analyzer:{analyzer_name}, "
                f"observable_classification:{observable_classification}, "
                f"observable_name:{observable_name}, RequestException {error}"
            )
            logger.error(error_message)
            report["errors"].append(error_message)
            report["success"] = False
    else:
        error_message = (
            f"job_id:{job_id}, analyzer:{analyzer_name}, "
            f"observable_classification:{observable_classification}, "
            f"observable_name:{observable_name}, "
            f"cannot analyze something different from domain"
        )
        logger.error(error_message)
        report["errors"].append(error_message)
        report["success"] = False


def _doh_cloudflare(
    job_id, analyzer_name, observable_classification, observable_name, report
):
    if observable_classification == "domain":
        try:
            client = requests.session()
            params = {
                "name": observable_name,
                "type": "A",
                "ct": "application/dns-json",
            }
            response = client.get("https://cloudflare-dns.com/dns-query", params=params)
            response.raise_for_status()
            response_dict = response.json()

            response_answer = response_dict.get("Answer", [])
            # first resolution or NXDOMAIN if domain does not exist
            result_data = (
                response_answer[0].get("data", "NXDOMAIN")
                if response_answer
                else "NXDOMAIN"
            )

            report["report"] = {"name": observable_name, "resolution": result_data}
        except requests.exceptions.RequestException as error:
            error_message = (
                f"job_id:{job_id}, analyzer:{analyzer_name}, "
                f"observable_classification:{observable_classification}, "
                f"observable_name:{observable_name}, RequestException {error}"
            )
            logger.error(error_message)
            report["errors"].append(error_message)
            report["success"] = False
    else:
        error_message = (
            f"job_id:{job_id}, analyzer:{analyzer_name}, "
            f"observable_classification:{observable_classification}, "
            f"observable_name:{observable_name}, "
            f"cannot analyze something different from domain"
        )
        logger.error(error_message)
        report["errors"].append(error_message)
        report["success"] = False


def _doh_cloudflare_malware(
    job_id, analyzer_name, observable_classification, observable_name, report
):
    if observable_classification == "domain":
        try:
            result = {"name": observable_name}

            client = requests.session()
            params = {
                "name": observable_name,
                "type": "A",
                "ct": "application/dns-json",
            }
            response = client.get(
                "https://security.cloudflare-dns.com/dns-query", params=params
            )
            response.raise_for_status()
            response_dict = response.json()

            response_answer = response_dict.get("Answer", [])
            if response_answer:
                resolution = response_answer[0].get("data", "")
                result["resolution"] = resolution
                # CloudFlare answers like this in case the domain is known as malicious
                if resolution == "0.0.0.0":
                    result["is_malicious"] = True
            else:
                logger.warning(
                    f"no Answer key retrieved for {observable_name} DNS request coming"
                    f" from {analyzer_name} analyzer"
                )
                result["no_answer"] = True

            report["report"] = result
        except requests.exceptions.RequestException as error:
            error_message = (
                f"job_id:{job_id}, analyzer:{analyzer_name}, "
                f"observable_classification:{observable_classification}, "
                f"observable_name:{observable_name}, RequestException {error}"
            )
            logger.error(error_message)
            report["errors"].append(error_message)
            report["success"] = False
    else:
        error_message = (
            f"job_id:{job_id}, analyzer:{analyzer_name}, "
            f"observable_classification:{observable_classification}, "
            f"observable_name:{observable_name}, "
            f"cannot analyze something different from domain"
        )
        logger.error(error_message)
        report["errors"].append(error_message)
        report["success"] = False


def _classic_dns(
    job_id, analyzer_name, observable_classification, observable_name, report
):
    result = {}
    if observable_classification == "ip":
        ipaddress.ip_address(observable_name)
        try:
            domains = socket.gethostbyaddr(observable_name)
            resolution = domains[0]
        except socket.herror:
            resolution = ""
        result = {"name": observable_name, "resolution": resolution}
    elif observable_classification == "domain":
        try:
            resolution = socket.gethostbyname(observable_name)
        except socket.gaierror:
            resolution = "NXDOMAIN"
        result = {"name": observable_name, "resolution": resolution}
    else:
        error_message = (
            f"job_id:{job_id}, analyzer:{analyzer_name}, "
            f"observable_classification: {observable_classification}, "
            f"observable_name:{observable_name}, not analyzable"
        )
        logger.error(error_message)
        report["errors"].append(error_message)
        report["success"] = False

    report["report"] = result
