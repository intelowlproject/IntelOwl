"""Module to retrieve active DNS resolution
"""

import requests
import ipaddress
import socket

from api_app.exceptions import AnalyzerConfigurationException
from api_app.script_analyzers import classes

import logging

logger = logging.getLogger(__name__)


class ActiveDNS(classes.ObservableAnalyzer):
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

    def set_config(self, additional_config_params):
        self.dns_type = additional_config_params.get("service", "")

    def run(self):
        if self.dns_type == "google":
            return self.__doh_google()
        if self.dns_type == "cloudflare":
            return self.__doh_cloudflare()
        if self.dns_type == "cloudflare_malware":
            return self.__doh_cloudflare_malware()
        if self.dns_type == "classic":
            return self.__classic_dns()

        raise AnalyzerConfigurationException(
            f"Service selected: {self.dns_type} is not available"
        )

    def __handle_activedns_error(self, err: str):
        error_message = (
            f"job_id:{self.job_id}, analyzer:{self.analyzer_name}, "
            f"observable_classification:{self.observable_classification}, "
            f"observable_name:{self.observable_name}, " + err
        )
        logger.error(error_message)
        self.report["errors"].append(error_message)
        self.report["success"] = False

    def __doh_google(self):
        if self.observable_classification == "domain":
            try:
                authority_answer = ""
                params = {
                    "name": self.observable_name,
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
                            f"observable: {self.observable_name} active_dns query"
                            f" retrieved no valid A answer: {answers}"
                        )
                self.report["report"] = {
                    "name": self.observable_name,
                    "resolution": ip,
                    "authoritative_answer": authority_answer,
                }
            except requests.exceptions.RequestException as err:
                self.__handle_activedns_error(
                    f"observable_name:{self.observable_name}, RequestException {err}"
                )
        else:
            self.__handle_activedns_error(
                "cannot analyze something different from type: domain"
            )

    def __doh_cloudflare(self):
        if self.observable_classification == "domain":
            try:
                client = requests.session()
                params = {
                    "name": self.observable_name,
                    "type": "A",
                    "ct": "application/dns-json",
                }
                response = client.get(
                    "https://cloudflare-dns.com/dns-query", params=params
                )
                response.raise_for_status()
                response_dict = response.json()

                response_answer = response_dict.get("Answer", [])
                # first resolution or NXDOMAIN if domain does not exist
                result_data = (
                    response_answer[0].get("data", "NXDOMAIN")
                    if response_answer
                    else "NXDOMAIN"
                )

                self.report["report"] = {
                    "name": self.observable_name,
                    "resolution": result_data,
                }
            except requests.exceptions.RequestException as err:
                self.__handle_activedns_error(
                    f"observable_name:{self.observable_name}, RequestException {err}"
                )
        else:
            self.__handle_activedns_error(
                "cannot analyze something different from type: domain"
            )

    def __doh_cloudflare_malware(self):
        if self.observable_classification == "domain":
            try:
                result = {"name": self.observable_name}

                client = requests.session()
                params = {
                    "name": self.observable_name,
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
                    # CloudFlare answers like this in case the domain is
                    # known as malicious
                    if resolution == "0.0.0.0":
                        result["is_malicious"] = True
                else:
                    logger.warning(
                        f"no Answer key retrieved for {self.observable_name}"
                        f"DNS request coming from {self.analyzer_name} analyzer"
                    )
                    result["no_answer"] = True

                self.report["report"] = result
            except requests.exceptions.RequestException as err:
                self.__handle_activedns_error(
                    f"observable_name:{self.observable_name}, RequestException {err}"
                )
        else:
            self.__handle_activedns_error(
                "cannot analyze something different from type: domain"
            )

    def __classic_dns(self):
        result = {}
        if self.observable_classification == "ip":
            ipaddress.ip_address(self.observable_name)
            resolutions = []
            try:
                domains = socket.gethostbyaddr(self.observable_name)
                resolutions = domains[2]
            except (socket.gaierror, socket.herror):
                logger.info(
                    f"no resolution found for observable {self.observable_name}"
                )
            result = {"name": self.observable_name, "resolutions": resolutions}
        elif self.observable_classification == "domain":
            try:
                resolution = socket.gethostbyname(self.observable_name)
            except socket.gaierror:
                resolution = "NXDOMAIN"
            result = {"name": self.observable_name, "resolution": resolution}
        else:
            self.__handle_activedns_error("not analyzable")

        self.report["report"] = result
