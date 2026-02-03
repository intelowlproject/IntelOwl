import logging
import re

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


IP_REG = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
IPv6_REG = (
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
EMAIL_REG = "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}"
DOMAIN_REG = re.compile(
    r"^(?:[a-zA-Z0-9]"  # First character of the domain
    r"(?:[a-zA-Z0-9-_]{0,61}[A-Za-z0-9])?\.)"  # Sub domain + hostname
    r"+[A-Za-z0-9][A-Za-z0-9-_]{0,61}"  # First 61 characters of the gTLD
    r"[A-Za-z]$"  # Last character of the gTLD
)
PHONE_REG = "^\+?[1-9]\d{1,14}$"
URL_REG = (
    "((http|https)://)(www.)?[a-zA-Z0-9@:%._\\+~#?&//=]{2,256}\\.[a-z]{2,6}\\b([-a-zA-Z0-9@:%._\\+~#?&//=]*)"
)


class IPQualityScore(classes.ObservableAnalyzer):
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

    def _get_url_payload(self):
        return {
            "strictness": self.url_strictness,
            "fast": str(self.url_fast).lower(),
            "timeout": self.url_timeout,
        }

    def _get_ip_payload(self):
        payload = {
            "strictness": self.ip_strictness,
            "allow_public_access_points": str(self.allow_public_access_points).lower(),
            "fast": str(self.ip_fast).lower(),
            "lighter_penalties": str(self.lighter_penalties).lower(),
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
        if re.match(IP_REG, self.observable_name) or re.match(IPv6_REG, self.observable_name):
            return self.IP_ENDPOINT, self._get_ip_payload()
        elif re.match(DOMAIN_REG, self.observable_name) or re.match(URL_REG, self.observable_name):
            return self.URL_ENDPOINT, self._get_url_payload()
        elif re.match(EMAIL_REG, self.observable_name):
            return self.EMAIL_ENDPOINT, self._get_email_payload()
        elif re.match(PHONE_REG, self.observable_name):
            return self.PHONE_ENDPOINT, self._get_phone_payload()
        else:
            return None, None

    def run(self):
        calling_endpoint, payload = self._get_calling_endpoint()
        ipqs_headers = {"IPQS-KEY": self._ipqs_api_key}

        try:
            if calling_endpoint and payload is not None:
                response = requests.get(
                    calling_endpoint + self.observable_name,
                    headers=ipqs_headers,
                    params=payload,
                )
                response.raise_for_status()
                result = response.json()
                return result
            else:
                logger.warning("Invalid or unsupported observable type")
                raise AnalyzerRunException("Invalid or unsupported observable type")
        except requests.RequestException as e:
            raise AnalyzerRunException(e)
