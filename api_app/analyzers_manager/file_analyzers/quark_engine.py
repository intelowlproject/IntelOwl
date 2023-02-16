# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from quark import freshquark
from quark.config import DIR_PATH
from quark.report import Report

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.exceptions import AnalyzerRunException


class QuarkEngine(FileAnalyzer):
    QUARK_RULES_PATH = DIR_PATH

    @classmethod
    def _update(cls):
        # the rules are installed in config.HOME_DIR by default
        freshquark.download()

    def run(self):
        report = Report()
        # start analysis
        report.analysis(self.filepath, self.QUARK_RULES_PATH)
        # return json report
        json_report = report.get_report("json")
        if not json_report:
            raise AnalyzerRunException("json report can not be empty")
        return json_report
