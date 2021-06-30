# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import hashlib
import time
import mwdblib
import logging

from intel_owl import secrets

from api_app.exceptions import AnalyzerRunException
from api_app.helpers import get_binary
from api_app.analyzers_manager.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class MWDB_Scan(FileAnalyzer):
    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", "MWDB_KEY")
        self.__api_key = secrets.get_secret(self.api_key_name)
        self.upload_file = additional_config_params.get("upload_file", False)
        self.max_tries = additional_config_params.get("max_tries", 50)
        self.poll_distance = 5

    def file_analysis(self, file_info):
        return "karton" in file_info.metakeys.keys()

    def run(self):
        mwdb = mwdblib.MWDB(api_key=self.__api_key)
        binary = get_binary(self.job_id)
        query = str(hashlib.sha256(binary).hexdigest())

        if self.upload_file:
            logger.info(f"mwdb_scan uploading sample: {self.md5}")
            file_object = mwdb.upload_file(query, binary)
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
            except Exception:
                raise AnalyzerRunException(
                    "File not found in the MWDB. Set 'upload_file=true' "
                    "if you want to upload and poll results. "
                )
        result = {"data": file_info.data, "metakeys": file_info.metakeys}
        result["permalink"] = f"https://mwdb.cert.pl/file/{query}"
        return result
