# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
# mock_utils.py: useful utils for mocking requests and responses for testing
# flake8: noqa

from unittest import skipIf  # flake8: noqa
from unittest.mock import patch, MagicMock  # flake8: noqa
from django.conf import settings


# class for mocking responses
class MockResponse:
    def __init__(self, json_data, status_code, text="", content=b""):
        self.json_data = json_data
        self.status_code = status_code
        self.text = text
        self.content = content

    def json(self):
        return self.json_data

    @staticmethod
    def raise_for_status():
        pass


# a mock response class that has no operation
class MockResponseNoOp:
    def __init__(self, json_data, status_code):
        pass

    def search(self, *args, **kwargs):
        return {}

    def query(self, *args, **kwargs):
        return {}


# it is optional to mock requests
def if_mock(decorators: list):
    def apply_all(f):
        for d in reversed(decorators):
            f = d(f)
        return f

    return apply_all if settings.MOCK_CONNECTIONS else lambda x: x


def mock_connections(decorator):
    return decorator if settings.MOCK_CONNECTIONS else lambda x: x


def mocked_requests(*args, **kwargs):
    return MockResponse({}, 200)


def mocked_requests_noop(*args, **kwargs):
    return MockResponseNoOp({}, 200)


def mocked_docker_analyzer_get(*args, **kwargs):
    return MockResponse(
        {"key": "test", "returncode": 0, "report": {"test": "This is a test."}}, 200
    )


def mocked_docker_analyzer_post(*args, **kwargs):
    return MockResponse({"key": "test", "status": "running"}, 202)
