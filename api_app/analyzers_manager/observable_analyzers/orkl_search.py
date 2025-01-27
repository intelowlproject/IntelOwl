import logging

import requests

from api_app.analyzers_manager import classes
from api_app.choices import Classification
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class OrklSearch(classes.ObservableAnalyzer):
    url = "https://orkl.eu/api/v1"
    full: bool = False
    limit: int = 1000

    def update(self):
        pass

    def run(self):
        headers = {
            "accept": "application/json",
        }
        if self.observable_classification == Classification.HASH.value:
            response = requests.get(
                url=f"{self.url}/library/entry/sha1/{self.observable_name}",
                headers=headers,
            )
            if response.status_code == 404:
                return {
                    "message": "No LibraryEntry found with SHA1 hash",
                }
        else:
            response = requests.get(
                url=f"""{self.url}/library/search?query={self.observable_name}
                &full={self.full}&limit={self.limit}""",
                headers=headers,
            )

        response.raise_for_status()
        return response.json()

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
                                    "authors": "string",
                                    "created_at": "string",
                                    "deleted_at": {},
                                    "file_creation_date": "string",
                                    "file_modification_date": "string",
                                    "file_size": 0,
                                    "files": {
                                        "img": "string",
                                        "pdf": "string",
                                        "text": "string",
                                    },
                                    "id": "string",
                                    "language": "string",
                                    "plain_text": "string",
                                    "references": ["string"],
                                    "report_names": ["string"],
                                    "sha1_hash": "string",
                                    "sources": [
                                        {
                                            "created_at": "string",
                                            "deleted_at": {},
                                            "description": "string",
                                            "id": "string",
                                            "name": "string",
                                            "reports": [
                                                {
                                                    "authors": "string",
                                                    "created_at": "string",
                                                    "deleted_at": {},
                                                    "file_creation_date": "string",
                                                    "file_modification_date": "string",
                                                    "file_size": 0,
                                                    "id": "string",
                                                    "language": "string",
                                                    "plain_text": "string",
                                                    "references": ["string"],
                                                    "report_names": ["string"],
                                                    "sha1_hash": "string",
                                                    "sources": ["string"],
                                                    "threat_actors": ["string"],
                                                    "title": "string",
                                                    "updated_at": "string",
                                                }
                                            ],
                                            "updated_at": "string",
                                            "url": "string",
                                        }
                                    ],
                                    "threat_actors": [
                                        {
                                            "aliases": ["string"],
                                            "created_at": "string",
                                            "deleted_at": {},
                                            "id": "string",
                                            "main_name": "string",
                                            "reports": [
                                                {
                                                    "authors": "string",
                                                    "created_at": "string",
                                                    "deleted_at": {},
                                                    "file_creation_date": "string",
                                                    "file_modification_date": "string",
                                                    "file_size": 0,
                                                    "id": "string",
                                                    "language": "string",
                                                    "plain_text": "string",
                                                    "references": ["string"],
                                                    "report_names": ["string"],
                                                    "sha1_hash": "string",
                                                    "sources": ["string"],
                                                    "threat_actors": ["string"],
                                                    "title": "string",
                                                    "updated_at": "string",
                                                }
                                            ],
                                            "source_id": "string",
                                            "source_name": "string",
                                            "tools": ["string"],
                                            "updated_at": "string",
                                        }
                                    ],
                                    "title": "string",
                                    "ts_created_at": 0,
                                    "ts_creation_date": 0,
                                    "ts_modification_date": 0,
                                    "ts_updated_at": 0,
                                    "updated_at": "string",
                                }
                            ],
                            "message": "string",
                            "status": "string",
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
