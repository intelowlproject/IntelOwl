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

    getASN: str = "https://bgpranking-ng.circl.lu/ipasn_history/?ip="
    getASNRank: str = "https://bgpranking-ng.circl.lu/json/asn"
    getASNHistory: str = "https://bgpranking-ng.circl.lu/json/asn_history"
    observable_name: str
    period: int  # optional

    def update(self) -> bool:
        pass

    def run(self):
        logger.info("Running BGP_Ranking")

        final_response = {}

        # get ASN from ip
        try:
            logger.info(f"Extracting ASN from IP: {self.observable_name}")
            response = requests.get(self.getASN + self.observable_name)
            response.raise_for_status()
            response = response.json()
            asn = response.get("response", {}).popitem()[1].get("asn", None)
            if not asn:
                raise AnalyzerRunException(f"ASN not found in {response}")
            logger.info(f"ASN {asn} extracted from {self.observable_name}")

            # get ASN rank from extracted ASN
            logger.info(f"Extracting ASN rank and position from ASN: {asn}")
            response = requests.post(self.getASNRank, data=json.dumps({"asn": asn}))
            response.raise_for_status()
            response = response.json()
            final_response["asn_description"] = response["response"].get(
                "asn_description", None
            )
            final_response["asn_rank"] = response["response"]["ranking"].get(
                "rank", None
            )
            final_response["asn_position"] = response["response"]["ranking"].get(
                "position", None
            )
            if final_response["asn_rank"] is None:
                raise AnalyzerRunException(f"ASN rank not found in {response}")

            logger.info(
                f"""ASN rank: {final_response['asn_rank']},
                position: {final_response['asn_position']}"""
            )

            if self.period:
                # get ASN history from extracted ASN
                logger.info(f"Extracting ASN history for period: {self.period}")
                response = requests.post(
                    self.getASNHistory,
                    data=json.dumps({"asn": asn, "period": self.period}),
                )
                response.raise_for_status()
                response = response.json()
                final_response["asn_history"] = response["response"].get(
                    "asn_history", None
                )
                if final_response["asn_history"] is None:
                    raise AnalyzerRunException(f"ASN history not found in {response}")
                logger.info(f"ASN history: {final_response['asn_history']}")
            # we are using the ASN in a variable
            # initially to avoid repetitive calculations
            final_response["asn"] = asn
        except (
            requests.exceptions.RequestException,
            json.JSONDecodeError,
        ) as e:
            logger.error(f"Exception: {e}")
            raise AnalyzerRunException(f"AnalyzerRunException: {e}")

        return final_response

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
