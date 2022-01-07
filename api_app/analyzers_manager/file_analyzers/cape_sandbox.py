from typing import final
import requests
import time
from api_app.analyzers_manager.classes import FileAnalyzer
from tests.mock_utils import MockResponse, if_mock_connections, patch


class CAPEsandbox(FileAnalyzer):
    def set_params(self, params):
        self.__token = self._secrets["token"]
        self.__vm_name = params.get("VM_NAME", "win7x64_8")
    
    def run(self):
        API_URL : str = "https://www.capesandbox.com/apiv2/tasks/create/file/"
        headers = {
        'Authorization': f'Token {self.__token}',
        }

        files = {
            'file': (self.filename, self.read_file_bytes()),
        }

        data = {"machine" : self.__vm_name}

        response = requests.post(API_URL, headers = headers, files = files, data = data)
        response_json = response.json()
        if not response_json["error"]:
            to_respond = {}
            to_respond["result_url"] = response_json["url"]
            task_id = response_json["data"]["task_ids"][0]
            status_api = "https://www.capesandbox.com/apiv2/tasks/status/" + str(task_id)
            while True:
                r = requests.get(status_api, headers = headers)
                responded_json = r.json()
                error = responded_json["error"]
                data = responded_json["data"]
                if (not error) and (data == "reported" or data == "completed"):
                    report_url = "https://www.capesandbox.com/apiv2/tasks/get/report/" + str(task_id) + "/json"
                    final_request = requests.get(report_url, headers = headers)
                    final_json = final_request.json()
                    if final_json["error"]:
                        to_respond["response"] = final_json
                        return to_respond
                elif error:
                    return responded_json
                
                elif data == "running":
                    time.sleep(20)

        return response_json

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)