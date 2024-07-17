# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import pylnk3

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.constants import ObservableTypes

logger = logging.getLogger(__name__)


class LnkInfo(FileAnalyzer):
    def run(self):
        result = {"uris": []}

        args = pylnk3.parse(self.filepath).arguments.split()
        for a in args:
            if ObservableTypes.calculate(a) == ObservableTypes.URL:
                result["uris"].append(a)

        result["uris"] = list(set(result["uris"]))
        return result
