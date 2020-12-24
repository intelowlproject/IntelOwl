import hashlib
import time

from mwdblib import MWDB
from api_app.exceptions import AnalyzerRunException
from api_app.helpers import get_binary
from api_app.script_analyzers.classes import FileAnalyzer


class MWDB_Scan(FileAnalyzer):
    def Merge(self, dict1, dict2):
        res = {**dict1, **dict2}
        return res

    def set_config(self, additional_config_params):
        self.api_key = additional_config_params.get("api_key", None)
        self.upload_file = additional_config_params.get("upload_file", None)
        self.wait_time = additional_config_params.get("wait_time", None)

    def run(self):
        if not self.api_key:
            raise AnalyzerRunException(
                f"No API key retrieved with name: {self.api_key}"
            )

        mwdb = MWDB(api_key=self.api_key)
        binary = get_binary(self.job_id)
        query = str(hashlib.sha256(binary).hexdigest())

        if self.upload_file:
            file_object = mwdb.upload_file(str(query), binary)
            time.sleep(self.wait_time)
            file_object.flush()
            file_info = mwdb.query_file(file_object.data["id"])
        else:
            try:
                file_info = mwdb.query_file(query)
            except Exception:
                raise AnalyzerRunException(
                    """\
                    File not found in the MWDB. Set 'upload_file=1' \
                    if you want to upload and poll results. \
                    """
                )
        file_info.data = self.Merge(file_info.data, file_info.metakeys)
        return file_info.data
