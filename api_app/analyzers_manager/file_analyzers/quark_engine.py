# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.conf import settings
from quark import freshquark
from quark.report import Report

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.exceptions import AnalyzerRunException


class QuarkEngine(FileAnalyzer):
    @staticmethod
    def updater():
        freshquark.download()

    def run(self):
        report = Report()
        # start analysis
        report.analysis(self.filepath, settings.QUARK_RULES_PATH)
        # return json report
        json_report = report.get_report("json")
        if not json_report:
            raise AnalyzerRunException("json report can not be empty")
        return json_report
