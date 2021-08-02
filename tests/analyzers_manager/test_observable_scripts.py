# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import os

from api_app.analyzers_manager.constants import ObservableTypes

from . import _ObservableAnalyzersScriptsTestCase


# Observable Analyzer Test Cases


class IPAnalyzersTestCase(_ObservableAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "observable_name": os.environ.get("TEST_IP", "8.8.8.8"),
            "observable_classification": ObservableTypes.IP,
        }


class DomainAnalyzersTestCase(_ObservableAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "observable_name": os.environ.get("TEST_DOMAIN", "www.google.com"),
            "observable_classification": ObservableTypes.DOMAIN,
        }


class URLAnalyzersTestCase(_ObservableAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "observable_name": os.environ.get(
                "TEST_URL", "https://www.honeynet.org/projects/active/intel-owl/"
            ),
            "observable_classification": ObservableTypes.URL,
        }


class HashAnalyzersTestCase(_ObservableAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "observable_name": os.environ.get(
                "TEST_MD5", "446c5fbb11b9ce058450555c1c27153c"
            ),
            "observable_classification": ObservableTypes.HASH,
        }


class GenericAnalyzersTestCase(_ObservableAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "observable_name": os.environ.get("TEST_GENERIC", "email@example.com"),
            "observable_classification": ObservableTypes.GENERIC,
        }
