import hashlib
import time
import mwdblib

from api_app.exceptions import AnalyzerRunException
from api_app.helpers import get_binary
from api_app.script_analyzers.classes import FileAnalyzer


class MWDB_Scan(FileAnalyzer):
    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", None)
        self.upload_file = additional_config_params.get("upload_file", False)
        self.max_retries = additional_config_params.get("max_retries", 20)

    def run(self):
        if not self.api_key_name:
            raise AnalyzerRunException(
                f"No API key retrieved with name: {self.api_key_name}"
            )

        mwdb = mwdblib.MWDB(api_key=self.api_key_name)
        binary = get_binary(self.job_id)
        query = str(hashlib.sha256(binary).hexdigest())

        if self.upload_file:
            file_object = mwdb.upload_file(query, binary)
            file_object.flush()
            while self.max_retries:
                self.max_retries -= 1
                time.sleep(10)
                file_info = mwdb.query_file(file_object.data["id"])
                if "karton" in file_info.metakeys.keys():
                    break
                else:
                    continue
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
