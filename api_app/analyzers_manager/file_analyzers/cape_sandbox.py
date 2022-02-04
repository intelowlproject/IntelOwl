import logging
import time

import requests

from api_app.analyzers_manager.classes import AnalyzerRunException, FileAnalyzer
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class CAPEsandbox(FileAnalyzer):
    def set_params(self, params):
        self.__token = self._secrets["api_key_name"]
        self.__vm_name = params.get("VM_NAME", "win7x64_8")
        self.max_tries = params.get("max_tries", 50)
        self.poll_distance = params.get("poll_distance", 30)
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

        logger.info(f"[INFO] (Job: {self.job_id} -> Uploaded the file to CAPESandbox")
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

            """
                The above response is only returned when a sample that has been already
                uploaded once is uploaded again.

                If it has been then we can just check it's
                report by querying the CAPESandbox API with the md5 hash of
                the file.

                If it exists in their database and is readable by us,
                the following code further fetches it's information.
                response_json in this case should look somewhat like this:

            {
                'error': True,
                'error_value': 'Error adding task to database',
                'errors': [{
                    'filename.exe':
                        'Not unique, as unique option set on submit or in conf/web.conf'
                }]
            }
            """

            logger.info(
                f"[INFO] (Job: {self.job_id} -> "
                "File uploaded is already present in the database. "
                "Querying its information through it's md5 hash.."
            )

            status_id = self.__search_by_md5()
            gui_report_url = self.__base_url + "/submit/status/" + status_id
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

            response_json = to_respond

        return response_json

    def __search_by_md5(self) -> str:
        db_search_url = self.__base_url + "/apiv2/tasks/search/md5/" + self.md5

        try:
            q = self.__session.get(db_search_url)
            q.raise_for_status()

        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        data_list = q.json().get("data")
        if data_list:
            status_id_int = data_list[0].get("id")
            status_id = str(status_id_int)
            return status_id

        raise AnalyzerRunException(
            "'data' key in response isn't populated as expected."
        )

    def __poll_for_result(
        self,
        task_id,
    ) -> dict:
        status_api = self.__base_url + "/apiv2/tasks/status/" + str(task_id)
        for i in range(self.max_tries):
            logger.info(
                f"[POLLING] (Job: {self.job_id} -> "
                f"CAPEsandbox __poll_for_result #{i + 1}/{self.max_tries}"
            )
            try:
                r = self.__session.get(status_api)
                if r.status_code == 429:
                    logger.info(
                        f"[INFO] (Job: {self.job_id} -> "
                        "Rate limited by CAPESandbox API. "
                        f"Sleeping for {self.poll_distance} seconds."
                    )
                    time.sleep(self.poll_distance)
                else:
                    r.raise_for_status()
            except requests.RequestException as e:
                if i == self.max_tries - 1:
                    raise AnalyzerRunException(e)
                    # ^ Unhandled exception at the last trial raised.
                logger.info(
                    f"[WARNING] (Job: {self.job_id} -> "
                    f"Unhandled exception at poll attempt number: "
                    f"{i}/{self.max_tries}. Ignoring and proceeding.."
                )

            responded_json = r.json()
            error = responded_json.get("error")
            data = responded_json.get("data")

            logger.info(
                f"[INFO] (Job: {self.job_id} -> "
                f"Status of the CAPESandbox task: {data}"
            )

            if error:
                raise AnalyzerRunException(error)

            elif data in ("reported", "completed"):
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
                response_ = final_json
                return response_

            elif data in ("pending", "running", "processing"):
                if i == self.max_tries - 1:
                    raise AnalyzerRunException(f"Task still {data}. Polling has ended.")
                    """
                        At times, What I have noticed is that
                        CAPESandbox likes to leave your submission pending.
                        It has a proper pending queue.

                        Usually the status changes like this:
                        pending -> running -> processing -> completed -> reported
                    """
                logger.info(
                    f"[INFO] (Job: {self.job_id} ->"
                    f"Poll number {i + 1}/{self.max_tries} completed."
                    f"Sleeping for {self.poll_distance} seconds before next attempt."
                )
                time.sleep(self.poll_distance)

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.Session.get",
                    return_value=MockResponse(
                        {"error": False, "data": "completed"}, 200
                    ),
                ),
                patch(
                    "requests.Session.post",
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
