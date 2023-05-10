# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
"""
mock_utils.py: useful utils for mocking requests and responses for testing
for observable analyzers, if can customize the behavior based on:
MOCK_CONNECTIONS to True -> connections to external analyzers are faked
"""

from dataclasses import dataclass
from unittest import skip, skipIf  # noqa: F401
from unittest.mock import MagicMock, patch  # noqa: F401

from django.conf import settings


class MockUpRequest:
    def __init__(self, user):
        self.user = user


# class for mocking responses
class MockUpResponse:
    @dataclass()
    class Request:
        def __init__(self):
            self.url = None

    def __init__(
        self, json_data, status_code, text="", content=b"", url="", headers=None
    ):
        self.json_data = json_data
        self.status_code = status_code
        self.text = text
        self.content = content
        self.url = url
        self.headers = headers or {}
        self.request = self.Request()

    def json(self):
        return self.json_data

    @staticmethod
    def raise_for_status():
        pass


# a mock response class that has no operation
class MockResponseNoOp:
    def __init__(self, json_data, status_code):
        pass

    @staticmethod
    def search(*args, **kwargs):
        return {}

    @staticmethod
    def query(*args, **kwargs):
        return {}


def if_mock_connections(*decorators):
    def apply_all(f):
        for d in reversed(decorators):
            f = d(f)
        return f

    return apply_all if settings.MOCK_CONNECTIONS else lambda x: x
