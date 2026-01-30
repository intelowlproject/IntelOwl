import logging

from polyswarm_api.api import PolyswarmAPI

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

from ...choices import Classification
from ..file_analyzers.polyswarm import PolyswarmBase

logger = logging.getLogger(__name__)


class PolyswarmObs(ObservableAnalyzer, PolyswarmBase):
    def run(self):
        api = PolyswarmAPI(key=self._api_key, community=self.polyswarm_community)
        if self.observable_classification == Classification.HASH.value:
            results = api.search(self.observable_name)
            result = self.get_results(results)
            return result
        elif self.observable_classification == Classification.DOMAIN.value:
            # https://docs.polyswarm.io/consumers/polyswarm-customer-api-v3#ioc-searching
            return api.check_known_hosts(domains=[self.observable_name])[0].json()

        elif self.observable_classification == Classification.IP.value:
            return api.check_known_hosts(ips=[self.observable_name])[0].json()

    def get_results(self, results):
        for result in results:  # should run only once
            if result.failed:
                raise AnalyzerRunException(f"Failed to get results from Polyswarm for {self.observable_name}")
            if not result.assertions:
                raise AnalyzerRunException(
                    f"Failed to get assertions from Polyswarm for {self.observable_name}"
                )
            return self.construct_result(result)
