# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import re

import pylnk3

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.choices import Classification

logger = logging.getLogger(__name__)


class LnkInfo(FileAnalyzer):
    def update(self) -> bool:
        pass

    def run(self):
        result = {"uris": []}
        try:
            parsed = pylnk3.parse(self.filepath)
        except Exception as e:
            error_message = f"job_id {self.job_id} cannot parse lnk file. Error: {e}"
            logger.warning(error_message, stack_info=False)
            self.report.errors.append(error_message)
        else:
            if arguments := getattr(parsed, "arguments", None):
                args = arguments.split()
                for a in args:
                    if Classification.calculate_observable(a) == Classification.URL:
                        # remove strings delimiters used in commands
                        a = re.sub(r"[\"\']", "", a)
                        result["uris"].append(a)

        result["uris"] = list(set(result["uris"]))
        return result
