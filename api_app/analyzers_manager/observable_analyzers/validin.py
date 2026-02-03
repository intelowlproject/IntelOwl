import logging

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (  # AnalyzerConfigurationException
    AnalyzerRunException,
)

logger = logging.getLogger(__name__)


class Validin(classes.ObservableAnalyzer):
    """
    This analyzer is a wrapper for the Validin project.
    """

    # this is a framework implication
    def update(self) -> bool:
        pass

    url: str = "https://app.validin.com"
    observable_classification: str
    observable_name: str
    scan_choice: str
    _api_key_name: str

    def _run_all_queries(self, endpoints, headers):
        final_response = {}
        if self.observable_classification in endpoints:
            for query_name, query_url in (endpoints.get(self.observable_classification)).items():
                logger.info(f"Executing query {query_name}")
                try:
                    response = requests.get(self.url + query_url, headers=headers)
                    if response.status_code != 200:
                        logger.error(f"Query {query_name} failed")

                        # we wont stop other quries from executing if one fails
                    final_response[f"{query_name}"] = response.json()
                except requests.RequestException as e:
                    raise AnalyzerRunException(e)
            return final_response
        else:
            raise AnalyzerRunException("Invalid classification")

    def _run_specific_query(self, endpoints, headers):
        if self.observable_classification in endpoints:
            try:
                query_url = endpoints[self.observable_classification][self.scan_choice]
                response = requests.get(self.url + query_url, headers=headers)
                return response.json()
            except KeyError:
                raise AnalyzerRunException(
                    f"Nothing in {self.scan_choice} for {self.observable_classification}"
                )
            except requests.RequestException as e:
                raise AnalyzerRunException(e)
        else:
            raise AnalyzerRunException("Invalid classification")

    def run(self):
        # code is structured in a way that endpoints
        # (that are in beta stage for now) can be added easily in the future
        # just add the endpoint in the dictionary with appropriate scan
        # choice and classification and the code will handle it
        # endpoint={classification:{scan_choice:query_url}}
        endpoints = {
            "domain": {
                "all_records": f"/api/axon/domain/dns/history/{self.observable_name}",
                "a_records": f"/api/axon/domain/dns/history/{self.observable_name}/A",
                "aaaa_rec": f"/api/axon/domain/dns/history/{self.observable_name}/AAAA",
                "ns_records": f"/api/axon/domain/dns/history/{self.observable_name}/NS",
                "ns_for": f"/api/axon/domain/dns/history/{self.observable_name}/NS_FOR",
                "ptr_records": f"/api/axon/domain/dns/hostname/{self.observable_name}",
                "live_dns_query": f"/api/axon/domain/dns/live/{self.observable_name}",
            },
            "ip": {
                "dns_hist_rev_ip": f"/api/axon/ip/dns/history/{self.observable_name}",
                "ptr_records": f"/api/axon/ip/dns/hostname/{self.observable_name}",
                # here provide the ip address in the format of: 192.168.1.0/24
                "cidr_dns_history": f"/api/axon/ip/dns/history/{self.observable_name}",
                "ptr_records_cidr": f"/api/axon/ip/dns/hostname/{self.observable_name}",
            },
            "health": "/api/ping",
        }
        headers = {
            "Authorization": f"BEARER {self._api_key_name}",
        }

        # will run all available quries for the observable if default
        if self.scan_choice == "default":
            return self._run_all_queries(endpoints, headers)
        else:
            return self._run_specific_query(endpoints, headers)
