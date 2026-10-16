# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from ipaddress import AddressValueError, IPv4Address
from urllib.parse import urlparse

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification


class PhishStats(ObservableAnalyzer):
    """
    Analyzer that uses PhishStats API to check if the observable
    is a phishing site.
    """

    url: str = "https://api.phishstats.info/api/phishing"

    @classmethod
    def update(cls) -> bool:
        return True

    # Mark the observable as malicious only when PhishStats returns
    # an actual matching record.
    def _do_create_data_model(self) -> bool:
        return super()._do_create_data_model() and bool(self.report.report.get("results"))

    def __build_phishstats_url(self) -> tuple[str, dict]:
        observable_classification = self.observable_classification
        observable_name = self.observable_name

        if observable_classification == Classification.URL:
            parsed_url = urlparse(observable_name)
            observable_name = parsed_url.hostname

            if not observable_name or not parsed_url.scheme:
                raise AnalyzerRunException("Invalid URL observable")

            try:
                IPv4Address(observable_name)
            except AddressValueError:
                observable_classification = Classification.DOMAIN
            else:
                observable_classification = Classification.IP

        if not observable_name:
            raise AnalyzerRunException("Invalid PhishStats observable")

        if observable_classification == Classification.IP:
            where = f"(ip,eq,{observable_name})"

        elif observable_classification == Classification.DOMAIN:
            where = f"(url,like,~{observable_name}~)"

        elif observable_classification == Classification.GENERIC:
            where = f"(title,like,~{observable_name}~)"

        else:
            raise AnalyzerRunException("PhishStats requires an IP, URL, Domain or Generic observable")

        params = {
            "_where": where,
            "_sort": "-date",
        }

        return self.url, params

    def run(self):
        api_url, params = self.__build_phishstats_url()

        response = requests.get(
            api_url,
            params=params,
            timeout=30,
        )
        response.raise_for_status()

        results = response.json()

        return {
            "api_url": response.url,
            "results": results,
        }
