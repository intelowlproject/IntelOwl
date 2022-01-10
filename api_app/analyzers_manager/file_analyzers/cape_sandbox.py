import time

import requests

from api_app.analyzers_manager.classes import AnalyzerRunException, FileAnalyzer
from tests.mock_utils import MockResponse, if_mock_connections, patch


class CAPEsandbox(FileAnalyzer):
    max_tries: int = 25
    to_respond = {}

    def set_params(self, params):
        self.__token = self._secrets["token"]
        self.__vm_name = params.get("VM_NAME", "win7x64_8")
        self.BASE_URL = self._secrets.get("url_key_name", "https://www.capesandbox.com")

    def run(self):
        API_URL: str = self.BASE_URL + "/apiv2/tasks/create/file/"
        self.headers = {
            "Authorization": f"Token {self.__token}",
        }

        files = {
            "file": (self.filename, self.read_file_bytes()),
        }

        data = {"machine": self.__vm_name}

        try:
            response = requests.post(
                API_URL, headers=self.headers, files=files, data=data
            )
            response_json = response.json()
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        # since not None == True as well. This is a more precise way.
        if response_json.get("error") is False:
            self.to_respond["result_url"] = response_json.get("url")
            self.task_id = response_json.get("data").get("task_ids")[0]
            self.status_api = self.BASE_URL + "/apiv2/tasks/status/" + str(self.task_id)
            result = self.__poll_for_result()
            return result

        elif (
            list(response_json.get("errors")[0].values())[0]
            == "Not unique, as unique option set on submit or in conf/web.conf"
        ):
            db_search_url = self.BASE_URL + "/apiv2/tasks/search/md5/" + self.md5

            try:
                q = requests.get(db_search_url, headers=self.headers)
                q.raise_for_status()

            except requests.RequestException as e:
                raise AnalyzerRunException(e)

            status_id = str(q.json().get("data")[0].get("id"))
            gui_report_url = self.BASE_URL + "/analysis/" + status_id
            report_url = (
                self.BASE_URL + "/apiv2/tasks/get/report/" + status_id + "/json"
            )
            self.to_respond["result_url"] = gui_report_url

            try:
                final_request = requests.get(report_url, headers=self.headers)
            except requests.RequestException as e:
                raise AnalyzerRunException(e)

            final_json = final_request.json()
            self.to_respond["response"] = final_json

            return self.to_respond

        raise response_json

    def __poll_for_result(
        self,
    ):
        for i in range(self.max_tries):
            try:
                r = requests.get(self.status_api, headers=self.headers)
                r.raise_for_status()
            except requests.RequestException as e:
                if r.status_code == 429:
                    time.sleep(30)
                else:
                    raise AnalyzerRunException(e)

            responded_json = r.json()
            error = responded_json.get("error")
            data = responded_json.get("data")
            if not error and (data in ("reported", "completed")):
                report_url = (
                    self.BASE_URL
                    + "/apiv2/tasks/get/report/"
                    + str(self.task_id)
                    + "/json"
                )
                try:
                    final_request = requests.get(report_url, headers=self.headers)
                except requests.RequestException as e:
                    raise AnalyzerRunException(e)

                final_json = final_request.json()

                if final_json.get("error"):
                    self.to_respond["response"] = final_json
                    return self.to_respond

            elif error:
                raise AnalyzerRunException(error)

            elif data == "running":
                time.sleep(30)

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockResponse(
                        {"error": False, "data": "completed"}, 200
                    ),
                ),
                patch(
                    "requests.post",
                    return_value=MockResponse(
                        {
                            "error": False,
                            "data": {
                                "task_ids": [1234],
                            },
                            "errors": [],
                            "url": ["http://fake_url.com/submit/status/1234/"],
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
