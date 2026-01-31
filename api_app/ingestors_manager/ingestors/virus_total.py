import logging
from typing import Any, Dict, Iterable
from unittest.mock import patch

from django.utils import timezone

from api_app.ingestors_manager.classes import Ingestor
from api_app.mixins import VirusTotalv3BaseMixin
from tests.mock_utils import MockUpResponse, if_mock_connections

logger = logging.getLogger(__name__)


class VirusTotal(Ingestor, VirusTotalv3BaseMixin):
    # Download samples/IOCs that are up to X hours old
    hours: int
    # The query to execute
    query: str
    # Extract IOCs? Otherwise, download the file
    extract_IOCs: bool
    # VT API key
    _api_key_name: str

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        # An Ingestor does not have a corresponding job so we set the value to False,
        # the aim of the ingestors usually is to download data not to upload.
        self.force_active_scan = False

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self) -> Iterable[Any]:
        if "fs:" not in self.query:
            delta_hours = timezone.datetime.now() - timezone.timedelta(hours=self.hours)
            self.query = f"fs:{delta_hours.strftime('%Y-%m-%d%H:%M:%S')}+ " + self.query
        data = self._vt_intelligence_search(self.query, 300, "").get("data", {})
        logger.info(f"VT ingestor: Retrieved {len(data)} items from the query {self.query}")
        samples_hashes = [d["id"] for d in data]
        for sample_hash in samples_hashes:
            if self.extract_IOCs:
                iocs = self._vt_get_iocs_from_file(sample_hash)
                if iocs:
                    for category, ioc in iocs.items():
                        logger.info(f"Extracted {category} from VT sample {sample_hash}: {ioc}")
                        yield ioc
            else:
                logger.info(f"Downloading VT sample: {sample_hash}")
                if sample := self._vt_download_file(sample_hash):
                    yield sample

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                # first search query
                patch(
                    "requests.get",
                    side_effect=[
                        # for intelligence search
                        MockUpResponse(
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
                        # for relationships
                        MockUpResponse(
                            {
                                "data": {
                                    "id": "b665290bc6bba034a69c32f54862518a86a2dab93787a7e99daaa552c708b23a",
                                    "type": "file",
                                    "links": {"self": "redacted"},
                                    "relationships": {
                                        "contacted_urls": {
                                            "data": [
                                                {
                                                    "type": "url",
                                                    "id": "548d0ca19336d289e61ff43b87330780234e8461151b88a4a6b34fc5ba721dfe",
                                                    "context_attributes": {
                                                        "url": "https://docs.google.com/uc?id=0BxsMXGfPIZfSVzUyaHFYVkQxeFk&export=download"
                                                    },
                                                },
                                                {
                                                    "type": "url",
                                                    "id": "e24125e866d9b72a68ae4b1c457eba59ee6a060efe3a1adb61ec328f42e85b7d",
                                                    "context_attributes": {
                                                        "url": "https://www.dropbox.com/s/zhp1b06imehwylq/Synaptics.rar?dl=1"
                                                    },
                                                },
                                            ],
                                            "links": {
                                                "self": "redacted",
                                                "related": "redacted",
                                            },
                                        },
                                        "contacted_domains": {
                                            "data": [
                                                {
                                                    "type": "domain",
                                                    "id": "docs.google.com",
                                                },
                                                {"type": "domain", "id": "dropbox.com"},
                                                {"type": "domain", "id": "google.com"},
                                                {
                                                    "type": "domain",
                                                    "id": "www-env.dropbox-dns.com",
                                                },
                                                {
                                                    "type": "domain",
                                                    "id": "www.dropbox.com",
                                                },
                                            ],
                                            "links": {
                                                "self": "redacted",
                                                "related": "redacted",
                                            },
                                        },
                                        "contacted_ips": {
                                            "data": [
                                                {
                                                    "type": "ip_address",
                                                    "id": "108.177.119.113",
                                                },
                                                {
                                                    "type": "ip_address",
                                                    "id": "108.177.96.113",
                                                },
                                                {
                                                    "type": "ip_address",
                                                    "id": "162.125.1.18",
                                                },
                                                {
                                                    "type": "ip_address",
                                                    "id": "162.125.65.18",
                                                },
                                                {
                                                    "type": "ip_address",
                                                    "id": "172.253.117.100",
                                                },
                                                {
                                                    "type": "ip_address",
                                                    "id": "172.253.117.101",
                                                },
                                                {
                                                    "type": "ip_address",
                                                    "id": "172.253.117.102",
                                                },
                                                {
                                                    "type": "ip_address",
                                                    "id": "172.253.117.113",
                                                },
                                                {
                                                    "type": "ip_address",
                                                    "id": "172.253.117.138",
                                                },
                                                {
                                                    "type": "ip_address",
                                                    "id": "172.253.117.139",
                                                },
                                            ],
                                            "links": {
                                                "self": "redacted",
                                                "related": "redacted",
                                            },
                                        },
                                    },
                                }
                            },
                            status_code=200,
                            content=b"downloaded test file!",
                        ),
                    ],
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
