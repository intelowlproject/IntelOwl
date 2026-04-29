"""IPQualityScore observable analyzer using the IPQualityScore API.

This module implements the `IPQualityScore` analyzer which queries the
IPQualityScore service for URLs, IPs, emails, phones and credential leaks.
"""

import logging
import re

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)

IP_REG = (
    r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}"
    r"(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
)

IPV6_REG = (
    r"\b(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:"
    r"(?:(:[0-9a-fA-F]{1,4}){1,7}|:)|"
    r"fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"
    r"::(ffff(:0{1,4}){0,1}:){0,1}"
    r"((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
    r"(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|"
    r"([0-9a-fA-F]{1,4}:){1,4}:"
    r"((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
    r"(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b"
)

EMAIL_REG = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"

DOMAIN_REG = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-_]{0,61}[A-Za-z0-9])?\.)"
    r"+[A-Za-z0-9][A-Za-z0-9-_]{0,61}"
    r"[A-Za-z]$"
)

PHONE_REG = r"^\+?[0-9(). -]{7,20}$"

URL_REG = (
    r"((http|https)://)"
    r"(www\.)?"
    r"[a-zA-Z0-9@:%._\\+~#?&//=]{2,256}"
    r"\.[a-z]{2,6}\b"
    r"([-a-zA-Z0-9@:%._\\+~#?&//=]*)"
)


class IPQualityScore(classes.ObservableAnalyzer):
    """Observable analyzer for IPQualityScore service.

    Uses regex-based detection of the observable type and queries the
    corresponding IPQualityScore endpoint.
    """

    _ipqs_api_key: str
    url_timeout: int = 2
    url_strictness: int = 0
    url_fast: bool = False
    phone_strictness: int = 0
    enhanced_name_check: bool = False
    enhanced_line_check: bool = False
    country: str = ""
    user_language: str = None
    user_agent: str = None
    transaction_strictness: int = 0
    ip_strictness: int = 0
    mobile: bool = False
    lighter_penalties: bool = False
    ip_fast: bool = True
    allow_public_access_points: bool = True
    email_timeout: int = 7
    suggest_domain: bool = False
    email_strictness: int = 0
    email_fast: bool = True
    abuse_strictness: int = 0

    IPQS_BASE_URL = "https://ipqualityscore.com/api/json/"
    URL_ENDPOINT = IPQS_BASE_URL + "url?url="
    IP_ENDPOINT = IPQS_BASE_URL + "ip?ip="
    EMAIL_ENDPOINT = IPQS_BASE_URL + "email?email="
    PHONE_ENDPOINT = IPQS_BASE_URL + "phone?phone="
    USERNAME_ENDPOINT = IPQS_BASE_URL + "leaked/username?username="
    PASSWORD_ENDPOINT = IPQS_BASE_URL + "leaked/password?password="
    LEAKED_EMAILENDPOINT = IPQS_BASE_URL + "leaked/email?email="

    @classmethod
    def update(cls) -> bool:
        pass

    def _get_url_payload(self):
        return {
            "strictness": self.url_strictness,
            "fast": str(self.url_fast).lower(),
            "timeout": self.url_timeout,
        }

    def _get_ip_payload(self):
        payload = {
            "strictness": self.ip_strictness,
            "allow_public_access_points": (str(self.allow_public_access_points).lower()),
            "fast": str(self.ip_fast).lower(),
            "lighter_penalties": (str(self.lighter_penalties).lower()),
            "mobile": str(self.mobile).lower(),
            "transaction_strictness": self.transaction_strictness,
        }
        if self.user_agent:
            payload["user_agent"] = self.user_agent
        if self.user_language:
            payload["user_language"] = self.user_language
        return payload

    def _get_email_payload(self):
        return {
            "fast": str(self.email_fast).lower(),
            "timeout": self.email_timeout,
            "suggest_domain": str(self.suggest_domain).lower(),
            "strictness": self.email_strictness,
            "abuse_strictness": self.abuse_strictness,
        }

    def _get_phone_payload(self):
        return {
            "strictness": self.phone_strictness,
            "country": [self.country],
            "enhanced_line_check": str(self.enhanced_line_check).lower(),
            "enhanced_name_check": str(self.enhanced_name_check).lower(),
        }

    def _get_calling_endpoint(self):
        if re.match(IP_REG, self.observable_name) or re.match(IPV6_REG, self.observable_name):
            return {
                "type": "ip",
                "endpoint": self.IP_ENDPOINT,
                "payload": self._get_ip_payload(),
            }
        if re.match(DOMAIN_REG, self.observable_name) or re.match(URL_REG, self.observable_name):
            return {
                "type": "url",
                "endpoint": self.URL_ENDPOINT,
                "payload": self._get_url_payload(),
            }
        if re.match(EMAIL_REG, self.observable_name):
            return {
                "type": "email",
                "leaked_email_endpoint": self.LEAKED_EMAILENDPOINT,
                "email_endpoint": self.EMAIL_ENDPOINT,
                "payload": self._get_email_payload(),
            }
        if re.match(PHONE_REG, self.observable_name):
            return {
                "type": "phone",
                "endpoint": self.PHONE_ENDPOINT,
                "payload": self._get_phone_payload(),
            }
        return {
            "type": "credentials",
            "username_endpoint": self.USERNAME_ENDPOINT,
            "password_endpoint": self.PASSWORD_ENDPOINT,
        }

    def run(self):
        endpoints = self._get_calling_endpoint()
        ipqs_headers = {"IPQS-KEY": self._ipqs_api_key}

        try:
            if endpoints.get("type") == "credentials":
                return self._handle_credentials(endpoints, ipqs_headers)

            if endpoints.get("type") == "email":
                return self._handle_email(endpoints, ipqs_headers)

            if endpoints.get("type") in ["url", "phone", "ip"]:
                calling_endpoint = endpoints.get("endpoint")
                payload = endpoints.get("payload")
                response = requests.get(
                    calling_endpoint + self.observable_name,
                    headers=ipqs_headers,
                    params=payload,
                    timeout=60,
                )
                response.raise_for_status()
                return response.json()

            msg = "Invalid or unsupported observable type"
            logger.warning(msg)
            raise AnalyzerRunException(msg)
        except requests.RequestException as e:
            raise AnalyzerRunException(e) from e

    def _handle_credentials(self, endpoints, headers):
        username_endpoint = endpoints.get("username_endpoint")
        password_endpoint = endpoints.get("password_endpoint")

        response_username = requests.get(
            username_endpoint + self.observable_name,
            headers=headers,
            timeout=60,
        )
        response_username.raise_for_status()
        result_username = response_username.json()

        response_password = requests.get(
            password_endpoint + self.observable_name,
            headers=headers,
            timeout=60,
        )
        response_password.raise_for_status()
        result_password = response_password.json()

        return {
            "darkweb_leak_username_api_result": result_username,
            "darkweb_leak_password_api_result": result_password,
        }

    def _handle_email(self, endpoints, headers):
        leaked_email_endpoint = endpoints.get("leaked_email_endpoint")
        email_endpoint = endpoints.get("email_endpoint")
        email_payload = endpoints.get("payload")

        response_leaked = requests.get(
            leaked_email_endpoint + self.observable_name,
            headers=headers,
            timeout=60,
        )
        response_leaked.raise_for_status()
        result_leaked = response_leaked.json()

        response_email = requests.get(
            email_endpoint + self.observable_name,
            headers=headers,
            params=email_payload,
            timeout=60,
        )
        response_email.raise_for_status()
        result_email = response_email.json()

        return {
            "darkweb_leak_email_api_result": result_leaked,
            "email_reputation_api_result": result_email,
        }
