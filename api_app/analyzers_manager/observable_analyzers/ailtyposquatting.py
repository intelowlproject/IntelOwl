import logging
import math

from ail_typo_squatting import addDash, omission, subdomain

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class AilTypoSquatting(classes.ObservableAnalyzer):
    """
    wrapper for https://github.com/typosquatter/ail-typo-squatting
    """

    omission: bool = False
    subdomain: bool = False
    addDash: bool = False
    runall: bool = True

    def update(self) -> bool:
        pass

    def run(self):
        resultList = []
        response = {}
        limit = math.inf
        if self.runall or self.omission:
            response["omission"] = omission(
                domain=self.observable_name,
                resultList=resultList,
                verbose=False,
                limit=limit,
                givevariations=False,
                keeporiginal=False,
            )
        if self.runall or self.subdomain:
            response["subdomain"] = subdomain(
                domain=self.observable_name,
                resultList=resultList,
                verbose=False,
                limit=limit,
                givevariations=False,
                keeporiginal=False,
            )
        if self.runall or self.addDash:
            response["addDash"] = addDash(
                domain=self.observable_name,
                resultList=resultList,
                verbose=False,
                limit=limit,
                givevariations=False,
                keeporiginal=False,
            )
        else:
            raise AnalyzerRunException("No algo selected to run")
        return response
