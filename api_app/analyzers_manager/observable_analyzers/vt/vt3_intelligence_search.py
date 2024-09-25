# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.mixins import VirusTotalv3AnalyzerMixin
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class VirusTotalv3Intelligence(ObservableAnalyzer, VirusTotalv3AnalyzerMixin):
    url = "https://www.virustotal.com/api/v3/intelligence"

    limit: int
    order_by: str

    def run(self):
        return self._vt_intelligence_search(
            self.observable_name, self.limit, self.order_by
        )

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        {
                            "data": [
                                {
                                    "id": "b665290bc6bba034a69c32f54862518a86a2dab93787a7e99daaa552c708b23a",
                                    "type": "file",
                                    "links": {"self": "redacted"},
                                    "attributes": {
                                        "popular_threat_classification": {
                                            "popular_threat_category": [
                                                {
                                                    "count": 18,
                                                    "value": "downloader",
                                                },
                                                {"count": 10, "value": "trojan"},
                                            ],
                                            "suggested_threat_label": "downloader.orcinius/x97m",
                                            "popular_threat_name": [
                                                {"count": 9, "value": "orcinius"},
                                                {"count": 4, "value": "x97m"},
                                                {"count": 3, "value": "w97m"},
                                            ],
                                        },
                                        "size": 94332,
                                        "first_submission_date": 1726640386,
                                        "crowdsourced_ids_stats": {
                                            "high": 0,
                                            "medium": 0,
                                            "low": 0,
                                            "info": 1,
                                        },
                                        "trid": [],
                                        "type_description": "Office Open XML Spreadsheet",
                                        "magika": "XLSX",
                                        "names": ["universityform.xlsm"],
                                        "sigma_analysis_results": [],
                                        "sha1": "14760fbb7615b561f86d0d48b01e5ee1b163a860",
                                        "sandbox_verdicts": {},
                                        "type_tags": [
                                            "document",
                                            "msoffice",
                                            "spreadsheet",
                                            "excel",
                                            "xlsx",
                                        ],
                                        "threat_severity": {
                                            "version": 5,
                                            "threat_severity_level": "SEVERITY_HIGH",
                                            "threat_severity_data": {
                                                "popular_threat_category": "downloader",
                                                "num_gav_detections": 5,
                                            },
                                            "last_analysis_date": "1726640490",
                                            "level_description": "Severity HIGH because it was considered "
                                            "downloader. Other contributing factor was "
                                            "that it could not be run in sandboxes.",
                                        },
                                        "vhash": "1d6670848780bd2ccd6ec496a9ba15b4",
                                        "downloadable": True,
                                        "magic": "Microsoft Excel 2007+",
                                        "last_analysis_date": 1726640386,
                                        "unique_sources": 1,
                                        "type_tag": "xlsx",
                                        "available_tools": [],
                                        "total_votes": {
                                            "harmless": 0,
                                            "malicious": 0,
                                        },
                                        "sigma_analysis_stats": {
                                            "critical": 0,
                                            "high": 1,
                                            "medium": 1,
                                            "low": 1,
                                        },
                                        "exiftool": {},
                                        "ssdeep": "1536:CguZCa6S5khUItn3RWa4znOSjhLzVubGa/M1NIpPkUlB7583fjnc"
                                        "FYIISFI:CgugapkhltLaPjpzVw/Ms8ULavLc0",
                                        "tlsh": "T17C93F06B96303918E0647837D03F5DA26638621D1F02FE8C2D46F1CC7"
                                        "EEBB47764A898",
                                        "tags": [
                                            "write-file",
                                            "auto-open",
                                            "create-ole",
                                            "copy-file",
                                            "enum-windows",
                                            "exe-pattern",
                                            "run-file",
                                            "macros",
                                            "registry",
                                            "save-workbook",
                                            "url-pattern",
                                            "environ",
                                            "create-file",
                                            "xlsx",
                                            "open-file",
                                            "calls-wmi",
                                        ],
                                        "main_icon": {},
                                        "last_analysis_stats": {
                                            "malicious": 44,
                                            "suspicious": 0,
                                            "undetected": 22,
                                            "harmless": 0,
                                            "timeout": 0,
                                            "confirmed-timeout": 0,
                                            "failure": 1,
                                            "type-unsupported": 10,
                                        },
                                        "reputation": 0,
                                        "last_modification_date": 1726647690,
                                        "md5": "368d2b0498d7464cc23acab82a806841",
                                        "openxml_info": {},
                                        "last_analysis_results": {},
                                        "type_extension": "xlsx",
                                        "meaningful_name": "universityform.xlsm",
                                        "crowdsourced_ids_results": [],
                                        "creation_date": 1421340901,
                                        "sigma_analysis_summary": {
                                            "Sigma Integrated Rule Set (GitHub)": {
                                                "critical": 0,
                                                "high": 1,
                                                "medium": 1,
                                                "low": 1,
                                            }
                                        },
                                        "last_submission_date": 1726640386,
                                        "sha256": "b665290bc6bba034a69c32f54862518a86a2dab93787a7e99daaa552c708b23a",
                                        "times_submitted": 1,
                                        "crowdsourced_ai_results": [],
                                    },
                                },
                            ],
                            "meta": {
                                "total_hits": 1,
                                "allowed_orders": [
                                    "first_submission_date",
                                    "last_submission_date",
                                    "positives",
                                    "times_submitted",
                                    "size",
                                    "unique_sources",
                                ],
                                "days_back": 90,
                            },
                            "links": {"self": "redacted"},
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
