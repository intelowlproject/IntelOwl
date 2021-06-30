# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.exceptions import AnalyzerRunException

from quark.report import Report


class QuarkEngine(FileAnalyzer):
    def run(self):
        # new report object
        report = Report()
        # start analysis
        report.analysis(self.filepath, "/opt/deploy/quark-rules")
        # return json report
        json_report = report.get_report("json")
        if not json_report:
            raise AnalyzerRunException("json report can not be empty")
        return json_report
