import logging
import math

from ail_typo_squatting import runAll
from ail_typo_squatting.dns_local.resolving import dnsResolving

from api_app.analyzers_manager import classes
from tests.mock_utils import if_mock_connections, patch

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
        resultList = []
        response["algorithms"] = runAll(
            domain=self.observable_name,
            limit=math.inf,
            formatoutput="yara",
            pathOutput=None,
        )
        if self._job.tlp == self._job.TLP.CLEAR.value and self.dns_resolving:
            response["dnsResolving"] = dnsResolving(
                resultList=resultList, domain=self.observable_name, pathOutput=None
            )

        return response

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch.object(runAll, "runAll", return_value=None),
                patch.object(dnsResolving, "dnsResolving", return_value=None),
            )
        ]
        return super()._monkeypatch(patches=patches)
