import logging
from typing import Any, Iterable
from unittest.mock import patch

from api_app.ingestors_manager.classes import Ingestor
from api_app.mixins import VirusTotalv3AnalyzerMixin
from tests.mock_utils import MockUpResponse, if_mock_connections

logger = logging.getLogger(__name__)


# apply a filter to all query results, let's try to reduce the FPs
def filter_vt_search_results(result):
    file_to_download = []
    data = result.get("data", {})
    logger.info(f"Retrieved {len(data)} items from the query")
    for d in data:
        attributes = data.get("attributes", {})

        # https://virustotal.readme.io/reference/files
        threat_severity = attributes.get("threat_severity", {})
        threat_severity_level = threat_severity.get("threat_severity_level", "")

        if threat_severity_level in ("SEVERITY_MEDIUM", "SEVERITY_HIGH"):
            file_to_download.append(d["id"])
    logger.info(
        f"Filtered {len(data)-len(file_to_download)} FP elements, "
        f"processing {len(file_to_download)} samples"
    )
    return file_to_download


class VirusTotal(VirusTotalv3AnalyzerMixin, Ingestor):
    # Download samples/IOCs that are up to X hours old
    hours: int
    # The query to execute
    query: str
    # Extract IOCs? Otherwise, download the file
    extract_IOCs: bool

    @classmethod
    def update(cls) -> bool:
        pass

    # perform a query in VT and return the results
    def _search(self, query):
        logger.info(f"Running VirusTotal query: {query}")
        # ref: https://developers.virustotal.com/reference/intelligence-search
        params = {
            "query": query,
            "limit": 300,
            "order": "",
        }
        result, response = self._perform_get_request(
            self.url + "intelligence/search", params=params
        )
        return result

    def run(self) -> Iterable[Any]:
        if "fs:" not in self.query:
            self.query = f"fs:{self.hours}h+ " + self.query
        result = self._search(self.query)
        samples_hashes = filter_vt_search_results(result)
        for sample_hash in samples_hashes:
            if self.extract_IOCs:
                iocs = self._vt_get_iocs_from_file(sample_hash)
                for category, ioc in iocs.items():
                    logger.info(
                        f"Extracted {category} from VT sample {sample_hash}: {ioc}"
                    )
            else:
                logger.info(f"Downloading VT sample: {sample_hash}")
                yield self._vt_download_file(sample_hash)

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
