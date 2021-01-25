import hashlib
import time
import mwdblib
import logging

from api_app.exceptions import AnalyzerRunException
from api_app.helpers import get_binary
from api_app.script_analyzers.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class MWDB_Scan(FileAnalyzer):
    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", None)
        self.upload_file = additional_config_params.get("upload_file", False)
        self.max_tries = additional_config_params.get("max_tries", 50)
        self.poll_distance = 5

    def file_analysis(self, file_info):
        return "karton" in file_info.metakeys.keys()

    def run(self):
        if not self.api_key_name:
            raise AnalyzerRunException(
                f"No API key retrieved with name: {self.api_key_name}"
            )

        mwdb = mwdblib.MWDB(api_key=self.api_key_name)
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
        return result
