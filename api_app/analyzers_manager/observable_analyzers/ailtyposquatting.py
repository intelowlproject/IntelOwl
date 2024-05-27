import logging
import math

from ail_typo_squatting import runAll
from ail_typo_squatting.dns_local.resolving import dnsResolving

from api_app.analyzers_manager import classes

logger = logging.getLogger(__name__)


class AilTypoSquatting(classes.ObservableAnalyzer):
    """
    wrapper for https://github.com/typosquatter/ail-typo-squatting
    """

    dns_resolving: bool = False

    def update(self) -> bool:
        pass

    def run(self):
        response = {}
        logger.info(
            f"""running AilTypoSquatting on {self.observable_name}
                    with tlp {self._config.maximum_tlp}
                    and dns resolving {self.dns_resolving}"""
        )
        resultList = []
        resultList = runAll(
            domain=self.observable_name,
            limit=math.inf,
            formatoutput="yara",
            pathOutput=None,
        )
        response["algorithms"] = resultList

        if self._config.maximum_tlp == "CLEAR" and self.dns_resolving:
            response["dnsResolving"] = dnsResolving(
                resultList, domain=self.observable_name, pathOutput=None
            )

        return response
