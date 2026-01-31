# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from hfinger.analysis import hfinger_analyze

from api_app.analyzers_manager.classes import FileAnalyzer


class Hfinger(FileAnalyzer):
    """
    Create fingerprints of malware HTTP
    requests stored in pcap files.
    """

    fingerprint_report_mode: int = 2

    def run(self):
        reports = dict()
        reports["extraction"] = hfinger_analyze(self.filepath, self.fingerprint_report_mode)
        fingerprints = set()
        for report in reports["extraction"]:
            fingerprint = report.get("fingerprint", "")
            if fingerprint:
                fingerprints.add(fingerprint)
        reports["fingerprints_summary"] = list(fingerprints)
        return reports

    @classmethod
    def update(cls) -> bool:
        pass
