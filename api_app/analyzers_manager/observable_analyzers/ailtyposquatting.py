import logging
import math
import os
import shutil

from ail_typo_squatting import runAll
from ail_typo_squatting.dns_local.resolving import dnsResolving
from django.conf import settings

from api_app.analyzers_manager import classes
from intel_owl.settings._util import set_permissions

logger = logging.getLogger(__name__)


class AilTypoSquatting(classes.ObservableAnalyzer):
    """
    wrapper for https://github.com/typosquatter/ail-typo-squatting
    """

    dns_resolving: bool = False

    def update(self) -> bool:
        pass

    def run(self):
        reports_dir = settings.AILTYPO_REPORTS_PATH / f"ailtypo_{self.observable_name}"

        response = {}
        os.mkdir(reports_dir)
        set_permissions(reports_dir)

        resultList = []
        resultList = runAll(
            domain=self.observable_name,
            limit=math.inf,
            formatoutput="yara",
            pathOutput=reports_dir,
            verbose=False,
            givevariations=False,
            keeporiginal=False,
        )
        response["algorithms"] = resultList

        if self._config.maximum_tlp == "CLEAR" and self.dns_resolving:
            response["dnsResolving"] = dnsResolving(
                resultList, domain=self.observable_name, pathOutput=reports_dir
            )

        shutil.rmtree(reports_dir)
        return response
