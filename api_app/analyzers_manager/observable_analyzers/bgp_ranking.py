import json
from urllib.parse import urljoin

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class BGPRanking(classes.ObservableAnalyzer):
    base_url: str = "http://bgpranking.circl.lu/"

    address_family: str = "ipv4"
    asn_history: bool

    def is_up(self):
        r = self.session.head(self.base_url)
        return r.status_code == 200

    def run(self):
        uri = f"ipasn_history/?ip={self.observable_name}"

        try:
            response = requests.post(urljoin(self.base_url, uri))
            response.raise_for_status()

            asn = response.json()["response"][
                list(response.json()["response"].keys())[0]
            ]["asn"]

            to_query = {"asn": asn, "ipversion": self.address_family, "limit": 5}
            base_url = "https://bgpranking-ng.circl.lu"
            r = requests.session().post(
                urljoin(base_url, "json/asn"), data=json.dumps(to_query)
            )

            if self.asn_history:
                to_query = {"asn": asn, "period": 5}
                r_hist = requests.session().post(
                    urljoin(base_url, "json/asn_history"), data=json.dumps(to_query)
                )
                results = {
                    "asn": response.json(),
                    "asn_rank": r.json(),
                    "asn_history": r_hist.json(),
                }
            else:
                results = {"asn": response.json(), "asn_rank": r.json()}

        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return results

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
