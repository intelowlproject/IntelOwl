import logging
from typing import Any, Iterable
from unittest.mock import patch

import requests

from api_app.ingestors_manager.classes import Ingestor
from api_app.ingestors_manager.exceptions import IngestorRunException
from api_app.mixins import VirusTotalv3AnalyzerMixin
from tests.mock_utils import MockUpResponse, if_mock_connections

logger = logging.getLogger(__name__)


# apply a filter to all query results, let's try to reduce the FPs
def filter_vt_search_results(result):
    file_to_download = []
    data = result["data"]
    for d in data:
        attributes = d["attributes"]
        # https://virustotal.readme.io/reference/files
        if "threat_severity" in attributes:
            threat_severity = attributes["threat_severity"]
            if "threat_severity_level" in threat_severity and threat_severity[
                "threat_severity_level"
            ] in ("SEVERITY_MEDIUM", "SEVERITY_HIGH"):
                file_to_download.append(d["id"])
    return file_to_download


class VirusTotal(Ingestor, VirusTotalv3AnalyzerMixin):
    # Download samples that are up to X hours old
    hours: int
    # Run the query
    query: str
    # Extract IOCs? Otherwise, download the file
    extract_IOCs: bool

    @classmethod
    def update(cls) -> bool:
        pass

    # perform a query in VT and return the results
    def _search(self, query):
        # ref: https://developers.virustotal.com/reference/intelligence-search
        base_url = "https://www.virustotal.com/api/v3/intelligence"
        params = {
            "query": query,
            "limit": 300,
            "order": "",
        }
        try:
            response = requests.get(
                base_url + "/search", params=params, headers=self.headers
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise IngestorRunException(e)
        result = response.json()
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
