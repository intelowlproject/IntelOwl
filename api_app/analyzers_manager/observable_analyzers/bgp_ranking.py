import json
import logging

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class BGPRanking(classes.ObservableAnalyzer):
    """
    wrapper for https://github.com/D4-project/BGP-Ranking
    """

    observable_name: str
    period: int  # optional

    def update(self) -> bool:
        pass

    def run(self):
        logger.info("Running BGP_Ranking")
        urls = {
            "getASN": "https://bgpranking-ng.circl.lu/ipasn_history/?ip=",
            "getASNRank": "https://bgpranking-ng.circl.lu/json/asn",
            "getASNHistory": "https://bgpranking-ng.circl.lu/json/asn_history",
        }
        finalresposne = {}

        # get ASN from ip
        try:
            response = requests.get(urls["getASN"] + self.observable_name)
            response.raise_for_status()
            response = response.json()
            finalresposne["asn"] = response["response"][
                list(response["response"].keys())[0]
            ]["asn"]
            logger.info("ASN extracted from IP")

            # get ASN rank from extracted ASN

            response = requests.post(
                urls["getASNRank"], data=json.dumps({"asn": finalresposne["asn"]})
            )
            response.raise_for_status()
            response = response.json()
            finalresposne["asn_description"] = response["response"]["asn_description"]
            finalresposne["asn_rank"] = response["response"]["ranking"]["rank"]
            finalresposne["asn_position"] = response["response"]["ranking"]["position"]
            logger.info("ASN rank and position extracted from ASN")

            if self.period:
                # get ASN history from extracted ASN
                response = requests.post(
                    urls["getASNHistory"],
                    data=json.dumps(
                        {"asn": finalresposne["asn"], "period": self.period}
                    ),
                )
                response.raise_for_status()
                response = response.json()
                finalresposne["asn_history"] = response["response"]["asn_history"]
                logger.info("ASN history extracted from ASN")

        except (
            requests.exceptions.RequestException,
            TypeError,
            json.JSONDecodeError,
            KeyError,
            AttributeError,
        ) as e:
            # Handle various specific exceptions
            logger.error(f"Exception: {e}")
            raise AnalyzerRunException(f"AnalyzerRunException: {e}")

        return finalresposne

    @classmethod
    def _monkeypatch(cls):
        response = {
            "meta": {"ip": "143.255.153.0/24"},
            "response": {
                "2024-03-07T12:00:00": {
                    "asn": "264643",
                    "prefix": "143.255.153.0/24",
                    "source": "caida",
                }
            },
        }

        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(response, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
