# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import os

import requests
from django.test import SimpleTestCase

from api_app.helpers import get_default_requests_timeout, patch_requests_default_timeout


class RequestsDefaultTimeoutPatchTests(SimpleTestCase):
    def setUp(self):
        patch_requests_default_timeout()

    def test_injects_default_timeout_when_missing(self):
        session_request = requests.sessions.Session.request
        original = session_request._intelowl_original
        captured = {}

        def stub(self, method, url, **kwargs):
            captured["timeout"] = kwargs.get("timeout")
            return "ok"

        session_request._intelowl_original = stub
        try:
            result = requests.Session().request("GET", "http://example.com")
            self.assertEqual(result, "ok")
            self.assertEqual(captured["timeout"], get_default_requests_timeout())
        finally:
            session_request._intelowl_original = original

    def test_keeps_explicit_timeout(self):
        session_request = requests.sessions.Session.request
        original = session_request._intelowl_original
        captured = {}

        def stub(self, method, url, **kwargs):
            captured["timeout"] = kwargs.get("timeout")
            return "ok"

        session_request._intelowl_original = stub
        try:
            result = requests.Session().request("GET", "http://example.com", timeout=5)
            self.assertEqual(result, "ok")
            self.assertEqual(captured["timeout"], 5)
        finally:
            session_request._intelowl_original = original

    def test_timeout_can_be_configured_via_env(self):
        old_connect = os.environ.get("INTELOWL_REQUESTS_CONNECT_TIMEOUT")
        old_read = os.environ.get("INTELOWL_REQUESTS_READ_TIMEOUT")
        os.environ["INTELOWL_REQUESTS_CONNECT_TIMEOUT"] = "1.5"
        os.environ["INTELOWL_REQUESTS_READ_TIMEOUT"] = "2.5"

        try:
            session_request = requests.sessions.Session.request
            original = session_request._intelowl_original
            captured = {}

            def stub(self, method, url, **kwargs):
                captured["timeout"] = kwargs.get("timeout")
                return "ok"

            session_request._intelowl_original = stub
            try:
                requests.Session().request("GET", "http://example.com")
                self.assertEqual(captured["timeout"], (1.5, 2.5))
            finally:
                session_request._intelowl_original = original
        finally:
            if old_connect is None:
                os.environ.pop("INTELOWL_REQUESTS_CONNECT_TIMEOUT", None)
            else:
                os.environ["INTELOWL_REQUESTS_CONNECT_TIMEOUT"] = old_connect
            if old_read is None:
                os.environ.pop("INTELOWL_REQUESTS_READ_TIMEOUT", None)
            else:
                os.environ["INTELOWL_REQUESTS_READ_TIMEOUT"] = old_read
