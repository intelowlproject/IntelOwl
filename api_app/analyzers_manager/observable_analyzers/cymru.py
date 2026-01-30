# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import socket

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification

logger = logging.getLogger(__name__)


class Cymru(ObservableAnalyzer):
    def run(self):
        results = {}
        if self.observable_classification != Classification.HASH:
            raise AnalyzerRunException(f"observable type {self.observable_classification} not supported")

        hash_length = len(self.observable_name)
        if hash_length == 64:
            raise AnalyzerRunException("sha256 are not supported by the service")

        results["found"] = False
        # reference: https://team-cymru.com/community-services/mhr/
        # if the resolution works, this means that the file is reported
        # as malware by Cymru
        domains = None
        try:
            query_to_perform = f"{self.observable_name}.malware.hash.cymru.com"
            domains = socket.gethostbyaddr(query_to_perform)
        except (socket.gaierror, socket.herror):
            logger.info(f"observable {self.observable_name} not found in HMR DB")
        except socket.timeout:
            message = f"request for {self.observable_name} in HMR DB triggered timeout"
            logger.warning(message)
            self.report.errors.append(message)
            results["timeout"] = True
        except Exception as e:
            logger.exception(e)
            self.report.errors.append(e)
            results["unexpected_error"] = True

        if domains:
            results["found"] = True
            results["resolution_data"] = domains[2]

        return results
