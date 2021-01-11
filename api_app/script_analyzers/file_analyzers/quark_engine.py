from api_app.script_analyzers.classes import FileAnalyzer
from quark.report import Report


class QuarkEngine(FileAnalyzer):
    def run(self):
        # new report object
        report = Report()
        # start analysis
        report.analysis(self.filepath, "/opt/deploy/quark-rules")
        # return json report
        return report.get_report("json")
