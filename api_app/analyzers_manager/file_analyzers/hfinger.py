# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from hfinger.analysis import hfinger_analyze

from api_app.analyzers_manager.classes import FileAnalyzer
from tests.mock_utils import if_mock_connections, patch


class Hfinger(FileAnalyzer):
    """
    Create fingerprints of malware HTTP
    requests stored in pcap files.
    """

    fingerprint_report_mode: int = 2

    def run(self):
        reports = dict()
        reports["extraction"] = hfinger_analyze(
            self.filepath, self.fingerprint_report_mode
        )
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

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "hfinger.analysis.hfinger_analyze",
                    return_value=[
                        {
                            "epoch_time": "1388111476.787707000",
                            "ip_src": "192.168.1.138",
                            "ip_dst": "173.194.115.80",
                            "port_src": "49209",
                            "port_dst": "80",
                            "fingerprint": "2.4|1|0.5||2.4|1.2|GE|1|ac,ac-la,us-ag,\
                                ac-en,ho,co|ac:te-ht,ap-xh+xm,as-as/ac-la:75ef792f/\
                                us-ag:ca0c4d71/ac-en:gz,de/co:Ke-Al|||",
                        },
                        {
                            "epoch_time": "1388111477.142485000",
                            "ip_src": "192.168.1.138",
                            "ip_dst": "66.225.230.141",
                            "port_src": "49220",
                            "port_dst": "80",
                            "fingerprint": "1.5|3|1.0|html|||GE|1|ac,re,ac-la,us-ag,\
                                ac-en,ho,co|ac:te-ht,ap-xh+xm,as-as/ac-la:75ef792f/\
                                us-ag:ca0c4d71/ac-en:gz,de/co:Ke-Al|||",
                        },
                    ],
                )
            )
        ]

        return super()._monkeypatch(patches=patches)
