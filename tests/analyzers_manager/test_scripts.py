# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import os

from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer

from . import _ObservableAnalyzersScriptsTestCase


######### TEST CASES ########## noqa E266


class IPAnalyzersTestCase(_ObservableAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "observable_name": os.environ.get("TEST_IP", "8.8.8.8"),
            "observable_classification": AnalyzerConfigSerializer.ObservableTypes.IP,
        }

    @classmethod
    def setUpClass(cls):
        pass


class DomainAnalyzersTestCase(_ObservableAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "observable_name": os.environ.get("TEST_DOMAIN", "www.google.com"),
            "observable_classification": AnalyzerConfigSerializer.ObservableTypes.DOMAIN,  # noqa E501
        }

    @classmethod
    def setUpClass(cls):
        pass


class URLAnalyzersTestCase(_ObservableAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "observable_name": os.environ.get(
                "TEST_URL", "https://www.honeynet.org/projects/active/intel-owl/"
            ),
            "observable_classification": AnalyzerConfigSerializer.ObservableTypes.URL,
        }

    @classmethod
    def setUpClass(cls):
        pass


class HashAnalyzersTestCase(_ObservableAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "observable_name": os.environ.get(
                "TEST_MD5", "446c5fbb11b9ce058450555c1c27153c"
            ),
            "observable_classification": AnalyzerConfigSerializer.ObservableTypes.HASH,
        }

    @classmethod
    def setUpClass(cls):
        pass


class GenericAnalyzersTestCase(_ObservableAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "observable_name": os.environ.get("TEST_GENERIC", "email@example.com"),
            "observable_classification": AnalyzerConfigSerializer.ObservableTypes.GENERIC,  # noqa E501
        }

    @classmethod
    def setUpClass(cls):
        pass
