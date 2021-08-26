# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import hashlib
import time
import mwdblib
import logging

from api_app.exceptions import AnalyzerRunException
from api_app.analyzers_manager.classes import FileAnalyzer

from tests.mock_utils import patch, if_mock_connections, MagicMock

logger = logging.getLogger(__name__)


def mocked_mwdb_response(*args, **kwargs):
    attrs = {"data": {"id": "id_test"}, "metakeys": {"karton": "test_analysis"}}
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

    def run(self):
        result = {}
        binary = self.read_file_bytes()
        query = str(hashlib.sha256(binary).hexdigest())

        mwdb = mwdblib.MWDB(api_key=self.__api_key)

        if self.upload_file:
            logger.info(f"mwdb_scan uploading sample: {self.md5}")
            file_object = mwdb.upload_file(query, binary, private=self.private, public=self.public)
            file_object.flush()
            for _try in range(self.max_tries):
                logger.info(
                    f"mwdb_scan sample: {self.md5} polling for result try #{_try + 1}"
                )
                time.sleep(self.poll_distance)
                file_info = mwdb.query_file(file_object.data["id"])
                if self.file_analysis(file_info):
                    break
            if not self.file_analysis(file_info):
                raise AnalyzerRunException("max retry attempts exceeded")
        else:
            try:
                file_info = mwdb.query_file(query)
            except Exception as exc:
                err_msg = (
                    "Error: File not found in the MWDB. Set 'upload_file=true' "
                    "if you want to upload and poll results. "
                )
                logger.error((str(exc), err_msg))
                self.report.errors.append(str(exc))
                self.report.errors.append(err_msg)
                result["not_found"] = True
                return result

        result.update(
            data=file_info.data,
            metakeys=file_info.metakeys,
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
