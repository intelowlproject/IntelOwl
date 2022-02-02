import time

import requests

from api_app.analyzers_manager.classes import AnalyzerRunException, FileAnalyzer
from tests.mock_utils import MockResponse, if_mock_connections, patch


class CAPEsandbox(FileAnalyzer):
    max_tries: int = 25
    poll_distance = 30

    def set_params(self, params):
        self.__token = self._secrets["api_key_name"]
        self.__vm_name = params.get("VM_NAME", "win7x64_8")
        self.__base_url = self._secrets.get(
            "url_key_name", "https://www.capesandbox.com"
        )
        self.__session = requests.Session()
        self.__session.headers = {
            "Authorization": f"Token {self.__token}",
        }

    def run(self):
        api_url: str = self.__base_url + "/apiv2/tasks/create/file/"
        to_respond = {}

        try:
            response = self.__session.post(
                api_url,
                files={
                    "file": (self.filename, self.read_file_bytes()),
                },
                data={"machine": self.__vm_name},
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        response_json = response.json()

        if response_json.get("error") is False:
            to_respond["result_url"] = response_json.get("url")
            task_id = response_json.get("data").get("task_ids")[0]
            result = self.__poll_for_result(task_id=task_id)
            to_respond["response"] = result
            return to_respond

        elif (
            list(response_json.get("errors")[0].values())[0]
            == "Not unique, as unique option set on submit or in conf/web.conf"
        ):

            status_id = self.__search_by_md5()
            gui_report_url = self.__base_url + "/analysis/" + status_id
            report_url = (
                self.__base_url + "/apiv2/tasks/get/report/" + status_id + "/json"
            )
            to_respond["result_url"] = gui_report_url

            try:
                final_request = self.__session.get(
                    report_url,
                )
            except requests.RequestException as e:
                raise AnalyzerRunException(e)

            final_json = final_request.json()
            to_respond["response"] = final_json

            return to_respond

        return response_json

    def __search_by_md5(
        self,
    ):
        db_search_url = self.__base_url + "/apiv2/tasks/search/md5/" + self.md5

        try:
            q = self.__session.get(db_search_url)
            q.raise_for_status()

        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        status_id = str(q.json().get("data")[0].get("id"))

        return status_id

    def __poll_for_result(
        self,
        task_id,
    ):
        status_api = self.__base_url + "/apiv2/tasks/status/" + str(task_id)
        for i in range(self.max_tries):
            try:
                r = self.__session.get(status_api)
                if r.status_code == 429:
                    time.sleep(self.poll_distance)
                else:
                    r.raise_for_status()
            except requests.RequestException as e:
                raise AnalyzerRunException(e)

            responded_json = r.json()
            error = responded_json.get("error")
            data = responded_json.get("data")
            if not error and (data in ("reported", "completed")):
                report_url = (
                    self.__base_url
                    + "/apiv2/tasks/get/report/"
                    + str(task_id)
                    + "/json"
                )
                try:
                    final_request = self.__session.get(
                        report_url,
                    )
                    final_request.raise_for_status()
                except requests.RequestException as e:
                    raise AnalyzerRunException(e)

                final_json = final_request.json()

                if final_json.get("error"):
                    response_ = final_json
                    return response_

            elif error:
                raise AnalyzerRunException(error)

            elif data == "running":
                time.sleep(30)

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "Session.get",
                    return_value=MockResponse(
                        {"error": False, "data": "completed"}, 200
                    ),
                ),
                patch(
                    "Session.post",
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
