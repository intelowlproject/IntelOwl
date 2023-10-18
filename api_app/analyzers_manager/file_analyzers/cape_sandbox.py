# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import time
from tempfile import NamedTemporaryFile

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class CAPEsandbox(FileAnalyzer):
    class ContinuePolling(Exception):
        pass

    # Specify options for the analysis package (e.g. "name=value,name2=value2").
    options: str
    # Specify an analysis package.
    package: str
    # Specify an analysis timeout.
    timeout: int
    # Specify a priority for the analysis (1=low, 2=medium, 3=high).
    priority: int
    # Specify the identifier of a machine you want to use (empty = first available).
    machine: str
    # Specify the operating system platform you want to use (windows/darwin/linux).
    platform: str
    # Enable to take a memory dump of the analysis machine.
    memory: bool
    # Enable to force the analysis to run for the full timeout period.
    enforce_timeout: bool
    # Specify any custom value.
    custom: str
    # Specify tags identifier of a machine you want to use.
    tags: str
    # Specify an analysis route.
    route: str
    # Number of max tries while trying to poll the CAPESandbox API.
    max_tries: int
    # Seconds to wait before moving on to the next poll attempt.
    poll_distance: int
    # Python requests HTTP GET/POST timeout
    requests_timeout: int
    # Token for Token Auth.
    _api_key_name: str
    # URL for the CapeSandbox instance.
    _url_key_name: str
    # CapeSandbox SSL certificate (multiline string).
    _certificate: str

    @staticmethod
    def _clean_certificate(cert):
        return (
            cert.replace("-----BEGIN CERTIFICATE-----", "-----BEGIN_CERTIFICATE-----")
            .replace("-----END CERTIFICATE-----", "-----END_CERTIFICATE-----")
            .replace(" ", "\n")
            .replace("-----BEGIN_CERTIFICATE-----", "-----BEGIN CERTIFICATE-----")
            .replace("-----END_CERTIFICATE-----", "-----END CERTIFICATE-----")
        )

    def config(self):
        super().config()
        self.__cert_file = NamedTemporaryFile(mode="w")
        self.__cert_file.write(self._clean_certificate(self._certificate))
        self.__cert_file.flush()
        self.__session = requests.Session()
        self.__session.verify = self.__cert_file.name
        self.__session.headers = {
            "Authorization": f"Token {self._api_key_name}",
        }

    def run(self):
        api_url: str = self._url_key_name + "/apiv2/tasks/create/file/"
        to_respond = {}
        logger.info(f"Job: {self.job_id} -> " "Starting file upload.")

        cape_params_name = [
            "options",
            "package",
            "timeout",
            "priority",
            "machine",
            "platform",
            "memory",
            "enforce_timeout",
            "custom",
            "tags",
            "route",
        ]
        data = {
            name: getattr(self, name)
            for name in cape_params_name
            if getattr(self, name, None) is not None
        }

        try:
            response = self.__session.post(
                api_url,
                files={
                    "file": (self.filename, self.read_file_bytes()),
                },
                data=data,
                timeout=self.requests_timeout,
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        response_json = response.json()
        logger.debug(f"response received: {response_json}")
        response_error = response_json.get("error", False)

        if not response_error:
            task_id = response_json.get("data").get("task_ids")[0]
            result = self.__poll_for_result(task_id=task_id)
            to_respond["result_url"] = self._url_key_name + f"/submit/status/{task_id}/"
            to_respond["response"] = result
            logger.info(
                f"Job: {self.job_id} -> "
                "File uploaded successfully without any errors."
            )

        else:
            response_errors = response_json.get("errors", [])
            if response_errors:
                values = list(response_errors[0].values())
                if (
                    values
                    and values[0]
                    == "Not unique, as unique option set on submit or in conf/web.conf"
                ):
                    #    The above response is only returned when
                    #    a sample that has been already
                    #    uploaded once is uploaded again.

                    #    If it has been then we can just check it's
                    #    report by querying the CAPESandbox API with the md5 hash of
                    #    the file.

                    #    If it exists in their database and is readable by us,
                    #    the following code further fetches it's information.
                    #    response_json in this case should look somewhat like this:

                    # {
                    #    'error': True,
                    #    'error_value': 'Error adding task to database',
                    #    'errors': [{
                    #        'filename.exe':
                    #           'Not unique, as unique option set
                    #           on submit or in conf/web.conf'
                    #    }]
                    # }

                    logger.info(
                        f"Job: {self.job_id} -> "
                        "File uploaded is already present in the database. "
                        "Querying its information through it's md5 hash.."
                    )

                    status_id = self.__search_by_md5()
                    gui_report_url = self._url_key_name + "/submit/status/" + status_id
                    report_url = (
                        self._url_key_name
                        + "/apiv2/tasks/get/report/"
                        + status_id
                        + "/litereport"
                    )
                    to_respond["result_url"] = gui_report_url

                    try:
                        final_request = self.__session.get(
                            report_url, timeout=self.requests_timeout
                        )
                    except requests.RequestException as e:
                        raise AnalyzerRunException(e)

                    to_respond["response"] = final_request.json()

        return to_respond

    def __search_by_md5(self) -> str:
        db_search_url = self._url_key_name + "/apiv2/tasks/search/md5/" + self.md5

        try:
            q = self.__session.get(db_search_url, timeout=self.requests_timeout)
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
        logger.info(
            f"Job: {self.job_id} -> Sleeping for the entire duration of the analysis: {self.timeout}s"
        )
        time.sleep(self.timeout)

        results = None
        status_api = self._url_key_name + "/apiv2/tasks/status/" + str(task_id)
        for try_ in range(self.max_tries):
            attempt = try_ + 1
            try:
                logger.info(
                    f" Job: {self.job_id} -> "
                    f"Starting poll number #{attempt}/{self.max_tries}"
                )
                try:
                    request = self.__session.get(
                        status_api, timeout=self.requests_timeout
                    )
                    # 429 Rate Limit is caught by the raise_for_status
                    request.raise_for_status()
                except requests.RequestException as e:
                    raise self.ContinuePolling(f"RequestException {e}")

                # in case the request was ok
                responded_json = request.json()
                error = responded_json.get("error")
                data = responded_json.get("data")

                logger.info(
                    f"Job: {self.job_id} -> " f"Status of the CAPESandbox task: {data}"
                )

                if error:
                    raise AnalyzerRunException(error)

                if data in ("pending", "running", "processing"):
                    raise self.ContinuePolling(f"Task still {data}")

                if data in ("reported", "completed"):
                    report_url = (
                        self._url_key_name
                        + "/apiv2/tasks/get/report/"
                        + str(task_id)
                        + "/litereport"
                    )
                    try:
                        final_request = self.__session.get(
                            report_url, timeout=self.requests_timeout
                        )
                        final_request.raise_for_status()
                    except requests.RequestException as e:
                        raise AnalyzerRunException(e)

                    results = final_request.json()

                    # the task was being processed
                    if (
                        "error" in results
                        and results["error"]
                        and results["error_value"] == "Task is still being analyzed"
                    ):
                        raise self.ContinuePolling("Task still processing")

                    logger.info(
                        f" Job: {self.job_id} ->"
                        f"Poll number #{attempt}/{self.max_tries} fetched"
                        " the results of the analysis."
                        " stopping polling.."
                    )

                    break

                else:
                    raise AnalyzerRunException(
                        f"status {data} was unexpected. Check the code"
                    )

            except self.ContinuePolling as e:
                logger.info(
                    f"Job: {self.job_id} -> "
                    "Continuing the poll at attempt number: "
                    f"#{attempt}/{self.max_tries}. {e}. "
                    f"Sleeping for {self.poll_distance} seconds."
                )
                last_try = self.max_tries - 1
                if try_ != last_try:  # avoiding useless last sleep
                    time.sleep(self.poll_distance)

        if not results:
            raise AnalyzerRunException(f"{self.job_id} poll ended without results")
        return results

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.Session.get",
                    return_value=MockUpResponse(
                        {"error": False, "data": "completed"}, 200
                    ),
                ),
                patch(
                    "requests.Session.post",
                    return_value=MockUpResponse(
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
