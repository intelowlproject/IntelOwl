import json
import logging

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class BGPRanking(classes.ObservableAnalyzer):
    """
    wrapper for https://github.com/D4-project/BGP-Ranking
    """

    url: str
    timeout: int
    period: int  # optional

    def update(self) -> bool:
        pass

    def run(self):
        final_response = {}

        # get ASN from ip

        logger.info(f"Extracting ASN from IP: {self.observable_name}")
        response = requests.get(
            self.url + "/ipasn_history/?ip=" + self.observable_name,
            timeout=self.timeout,
        )
        response.raise_for_status()
        response = response.json()
        asn = response.get("response", {}).popitem()[1].get("asn", None)
        if not asn:
            raise AnalyzerRunException(f"ASN not found in {response}")
        logger.info(f"ASN {asn} extracted from {self.observable_name}")

        # get ASN rank from extracted ASN
        logger.info(f"Extracting ASN rank and position from ASN: {asn}")
        response = requests.post(
            self.url + "/json/asn",
            data=json.dumps({"asn": asn}),
            timeout=self.timeout,
        )
        response.raise_for_status()
        response = response.json()
        final_response["asn_description"] = response["response"].get("asn_description", None)
        final_response["asn_rank"] = response["response"]["ranking"].get("rank", None)
        final_response["asn_position"] = response["response"]["ranking"].get("position", None)
        if final_response["asn_rank"] is None:
            raise AnalyzerRunException(f"ASN rank not found in {response}")

        logger.info(
            f"""ASN rank: {final_response["asn_rank"]},
            position: {final_response["asn_position"]},
            from {self.observable_name}"""
        )

        if self.period:
            # get ASN history from extracted ASN
            logger.info(f"Extracting ASN history for period: {self.period}")
            response = requests.post(
                self.url + "/json/asn_history",
                data=json.dumps({"asn": asn, "period": self.period}),
                timeout=self.timeout,
            )
            response.raise_for_status()
            response = response.json()
            final_response["asn_history"] = response["response"].get("asn_history", None)
            if final_response["asn_history"] is None:
                raise AnalyzerRunException(f"ASN history not found in {response}")
            logger.info(
                f"""ASN history: {final_response["asn_history"]}
                for {self.observable_name}"""
            )
        # we are using the ASN in a variable
        # initially to avoid repetitive calculations
        final_response["asn"] = asn

        return final_response
