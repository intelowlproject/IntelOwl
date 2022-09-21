# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import hashlib
import logging
import time

import mwdblib
from requests import HTTPError

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MagicMock, if_mock_connections, patch

logger = logging.getLogger(__name__)


def mocked_mwdb_response(*args, **kwargs):
    attrs = {
        "data": {"id": "id_test", "children": [], "parents": []},
        "attributes": {"karton": "test_analysis"},
    }
    fileInfo = MagicMock()
    fileInfo.configure_mock(**attrs)
    QueryResponse = MagicMock()
    attrs = {"query_file.return_value": fileInfo}
    QueryResponse.configure_mock(**attrs)
    Response = MagicMock(return_value=QueryResponse)
    return Response.return_value


class MWDB_Scan(FileAnalyzer):
    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]
        self.upload_file = params.get("upload_file", False)
        self.private = params.get("private", True)
        self.public = not self.private
        self.max_tries = params.get("max_tries", 50)
        self.poll_distance = 5

    def file_analysis(self, file_info):
        return "karton" in file_info.metakeys.keys()

    def adjust_relations(self, base, key, recursive=True):
        new_relation = []
        for relation in base[key]:
            if relation["type"] == "file":
                new_relation.append(self.mwdb.query_file(relation["id"]).data)
            elif relation["type"] == "static_config":
                new_relation.append(self.mwdb.query_config(relation["id"]).data)
        base[key] = new_relation
        # HERE WE GO
        if recursive:
            for new_base in base[key]:
                if base["type"] == "file":

                    # otherwise we have an infinite loop
                    if key == "parents":
                        self.adjust_relations(new_base, key="parents", recursive=True)
                        self.adjust_relations(new_base, key="children", recursive=False)
                    elif key == "children":
                        self.adjust_relations(new_base, key="parents", recursive=True)
                        self.adjust_relations(new_base, key="children", recursive=False)

    def run(self):
        result = {}
        binary = self.read_file_bytes()
        query = str(hashlib.sha256(binary).hexdigest())
        self.mwdb = mwdblib.MWDB(api_key=self.__api_key)

        if self.upload_file:
            logger.info(f"mwdb_scan uploading sample: {self.md5}")
            file_object = self.mwdb.upload_file(
                query, binary, private=self.private, public=self.public
            )
            file_object.flush()
            for _try in range(self.max_tries):
                logger.info(
                    f"mwdb_scan sample: {self.md5} polling for result try #{_try + 1}"
                )
                time.sleep(self.poll_distance)
                file_info = self.mwdb.query_file(file_object.data["id"])
                if self.file_analysis(file_info):
                    break
            if not self.file_analysis(file_info):
                raise AnalyzerRunException("max retry attempts exceeded")
        else:
            try:
                file_info = self.mwdb.query_file(query)
            except HTTPError:
                result["not_found"] = True
                return result
            else:
                result["not_found"] = False
        # adding information about the children and parents
        self.adjust_relations(file_info.data, "parents", True)
        self.adjust_relations(file_info.data, "children", True)

        result.update(
            data=file_info.data,
            permalink=f"https://mwdb.cert.pl/file/{query}",
        )

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "mwdblib.MWDB",
                    side_effect=mocked_mwdb_response,
                ),
                patch.object(cls, "file_analysis", return_value=True),
            )
        ]
        return super()._monkeypatch(patches=patches)
