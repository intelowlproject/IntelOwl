import socket
import logging

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes


logger = logging.getLogger(__name__)


class Cymru(classes.ObservableAnalyzer):
    def run(self):
        results = {}
        if self.observable_classification != "hash":
            raise AnalyzerRunException(
                f"observable type {self.observable_classification} not supported"
            )

        results["found"] = False
        # reference: https://team-cymru.com/community-services/mhr/
        # if the resolution works, this means that the file is reported
        # as malware by Cymru
        resolutions = []
        try:
            query_to_perform = f"{self.observable_name}.malware.hash.cymru.com"
            domains = socket.gethostbyaddr(query_to_perform)
            resolutions = domains[2]
        except (socket.gaierror, socket.herror):
            logger.info(f"observable {self.observable_name} not found in HMR DB")
        if resolutions:
            results["found"] = True
        results["resolution_data"] = resolutions

        return results
