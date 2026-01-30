# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl

# See the file 'LICENSE' for copying permission.
import logging
import math

from ail_typo_squatting import typo
from ail_typo_squatting.dns_local import resolving

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
                    with tlp {self._job.tlp}
                    and dns resolving {self.dns_resolving}"""
        )

        response["algorithms"] = typo.runAll(
            domain=self.observable_name,
            limit=math.inf,
            formatoutput="text",
            pathOutput=None,
        )
        if self._job.tlp == self._job.TLP.CLEAR.value and self.dns_resolving:
            # for "x.com", response["algorithms"][0]=".com"
            # which is not valid for look up
            if len(self.observable_name.split(".")[0]) == 1:
                logger.info(
                    f"""running dns resolving on {self.observable_name}
                     excluding {response["algorithms"][0]}"""
                )
                response["dnsResolving"] = resolving.dnsResolving(
                    resultList=response["algorithms"][1:],
                    domain=self.observable_name,
                    pathOutput=None,
                )
            else:
                response["dnsResolving"] = resolving.dnsResolving(
                    resultList=response["algorithms"],
                    domain=self.observable_name,
                    pathOutput=None,
                )

        return response
