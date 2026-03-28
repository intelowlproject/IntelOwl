# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from django.test import SimpleTestCase
from requests import Response

from api_app.analyzers_manager.classes import DockerBasedAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException


class DockerBasedAnalyzerHttpErrorsTests(SimpleTestCase):
    def test_bad_request_with_non_json_body_raises_analyzer_run_exception(self):
        resp = Response()
        resp.status_code = 400
        resp._content = b""

        with self.assertRaises(AnalyzerRunException):
            DockerBasedAnalyzer._DockerBasedAnalyzer__raise_in_case_bad_request(
                "StringsInfo",
                resp,
            )

    def test_docker_run_normalizes_bytes_files_to_requests_file_tuples(self):
        captured = {}

        class FakeResponse:
            status_code = 200
            text = ""

            def json(self):
                return {"report": {"ok": True}}

        def stub_post(url, files=None, data=None, headers=None, **kwargs):
            captured["files"] = files
            captured["data"] = data
            captured["headers"] = headers
            return FakeResponse()

        class Dummy:
            url = "http://example.com/analyze"
            name = "Dummy"

            def __repr__(self):
                return "<Dummy>"

            def _raise_container_not_running(self):
                raise AssertionError

        with patch("api_app.analyzers_manager.classes.requests.post", side_effect=stub_post):
            result = DockerBasedAnalyzer._docker_run(
                Dummy(),
                req_data={"args": []},
                req_files={"sample.bin": b"123"},
                avoid_polling=True,
            )

        self.assertEqual(result, {"ok": True})
        self.assertEqual(captured["files"]["sample.bin"], ("sample.bin", b"123"))
        self.assertEqual(captured["headers"]["Host"], "localhost")
