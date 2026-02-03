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
    Analyzer that uses PhishStats API to check if the observable is a phishing site.
    """

    url: str = "https://api.phishstats.info/api"

    @classmethod
    def update(cls) -> bool:
        pass

    def __build_phishstats_url(self) -> str:
        to_analyze_observable_classification = self.observable_classification
        to_analyze_observable_name = self.observable_name
        if self.observable_classification == Classification.URL:
            to_analyze_observable_name = urlparse(self.observable_name).hostname
            try:
                IPv4Address(to_analyze_observable_name)
            except AddressValueError:
                to_analyze_observable_classification = Classification.DOMAIN
            else:
                to_analyze_observable_classification = Classification.IP

        if to_analyze_observable_classification == Classification.IP:
            endpoint = f"phishing?_where=(ip,eq,{to_analyze_observable_name})&_sort=-date"
        elif to_analyze_observable_classification == Classification.DOMAIN:
            endpoint = f"phishing?_where=(url,like,~{to_analyze_observable_name}~)&_sort=-date"
        elif to_analyze_observable_classification == Classification.GENERIC:
            endpoint = f"phishing?_where=(title,like,~{to_analyze_observable_name}~)&_sort=-date"
        else:
            raise AnalyzerRunException("Phishstats require either of IP, URL, Domain or Generic")
        return f"{self.url}/{endpoint}"

    def run(self):
        api_url = self.__build_phishstats_url()
        response = requests.get(api_url)
        response.raise_for_status()

        return {"api_url": api_url, "results": response.json()}
