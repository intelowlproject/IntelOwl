# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException


class QuarkEngine(FileAnalyzer):
    @classmethod
    def update(cls) -> bool:
        from quark import freshquark

        # the rules are installed in config.HOME_DIR by default
        freshquark.download()
        return True

    def run(self):
        from quark.config import DIR_PATH
        from quark.report import Report

        report = Report()
        # start analysis
        report.analysis(self.filepath, DIR_PATH)
        # return json report
        json_report = report.get_report("json")
        if not json_report:
            raise AnalyzerRunException("json report can not be empty")
        return json_report
