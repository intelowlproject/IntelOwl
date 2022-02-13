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

        logger.info(f"Job: {self.job_id} -> " "Starting file upload.")

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

            logger.info(
                f"Job: {self.job_id} -> "
                "File uploaded successfully without any errors."
            )

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
                f"Job: {self.job_id} -> "
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

            to_respond["response"] = final_request.json()

        return to_respond

    def __search_by_md5(self) -> str:
        db_search_url = self.__base_url + "/apiv2/tasks/search/md5/" + self.md5

        try:
            q = self.__session.get(db_search_url)
            q.raise_for_status()

        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        data_list = q.json().get("data")
        if not data_list:
            raise AnalyzerRunException(
                "'data' key in response isn't populated in __search_by_md5 as expected"
            )

        status_id_int = data_list[0].get("id")
        status_id = str(status_id_int)
        return status_id

    def __poll_for_result(
        self,
        task_id,
    ) -> dict:
        error_in_poll = False
        status_api = self.__base_url + "/apiv2/tasks/status/" + str(task_id)
        for i in range(self.max_tries):
            error_details = None

            logger.info(
                f" Job: {self.job_id} -> "
                f"Starting poll number #{i + 1}/{self.max_tries}"
            )
            try:
                r = self.__session.get(status_api)
                if r.status_code == 429:
                    logger.info(
                        f"Job: {self.job_id} -> "
                        "Rate limited by CAPESandbox API. "
                        f"Sleeping for {self.poll_distance} seconds."
                    )

                else:
                    r.raise_for_status()

                error_in_poll = False

            except requests.RequestException as e:
                error_in_poll = True
                error_details = e

                logger.exception(
                    f"Job: {self.job_id} -> "
                    f"Exception at poll attempt number: "
                    f"#{i}/{self.max_tries} : {e}"
                    " Ignoring and proceeding.."
                )
                logger.error(e)

            responded_json = r.json()
            error = responded_json.get("error")
            data = responded_json.get("data")

            logger.info(
                f"Job: {self.job_id} -> " f"Status of the CAPESandbox task: {data}"
            )

            if error:
                raise AnalyzerRunException(error)

            elif data in ("pending", "running", "processing"):
                error_details = f"Task still {data}. Polling has ended."

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

                logger.info(
                    f" Job: {self.job_id} ->"
                    f"Poll number #{i + 1}/{self.max_tries} fetched"
                    " the results of the analysis."
                    " stopping polling.."
                )

                final_json = final_request.json()
                return final_json

            logger.info(
                f"Job: {self.job_id} -> "
                f"Analysis status: {data}. "
                f"Sleeping for {self.poll_distance} seconds before next attempt."
            )
            time.sleep(self.poll_distance)

        if error_in_poll:
            """
            Only triggered if there is an exception in the
            very last poll.
            """
            raise AnalyzerRunException(error_details)

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
