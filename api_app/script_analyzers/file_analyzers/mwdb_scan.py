import hashlib
import time
import mwdblib

# from mwdblib import MWDB
from api_app.exceptions import AnalyzerRunException
from api_app.helpers import get_binary
from api_app.script_analyzers.classes import FileAnalyzer


class MWDB_Scan(FileAnalyzer):
    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", None)
        self.upload_file = additional_config_params.get("upload_file", False)

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
            while True:
                file_info = mwdb.query_file(file_object.data["id"])
                time.sleep(10)
                if not ("karton" in file_info.metakeys.keys()):
                    continue
                else:
                    break
        else:
            try:
                file_info = mwdb.query_file(query)
            except Exception:
                raise AnalyzerRunException(
                    "File not found in the MWDB. Set 'upload_file=true' "
                    "if you want to upload and poll results. "
                )
        result = {"data": {}, "metakeys": {}}
        result["data"] = file_info.data
        result["metakeys"] = file_info.metakeys
        return result
