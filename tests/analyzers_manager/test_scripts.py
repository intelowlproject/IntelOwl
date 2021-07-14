# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import os

from api_app.analyzers_manager.constants import ObservableTypes

from . import _ObservableAnalyzersScriptsTestCase, _FileAnalyzersScriptsTestCase


#### Observable Analyzer Test Cases ####


class IPAnalyzersTestCase(_ObservableAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "observable_name": os.environ.get("TEST_IP", "8.8.8.8"),
            "observable_classification": ObservableTypes.IP.value,
        }


class DomainAnalyzersTestCase(_ObservableAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "observable_name": os.environ.get("TEST_DOMAIN", "www.google.com"),
            "observable_classification": ObservableTypes.DOMAIN.value,
        }


class URLAnalyzersTestCase(_ObservableAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "observable_name": os.environ.get(
                "TEST_URL", "https://www.honeynet.org/projects/active/intel-owl/"
            ),
            "observable_classification": ObservableTypes.URL.value,
        }


class HashAnalyzersTestCase(_ObservableAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "observable_name": os.environ.get(
                "TEST_MD5", "446c5fbb11b9ce058450555c1c27153c"
            ),
            "observable_classification": ObservableTypes.HASH.value,
        }


class GenericAnalyzersTestCase(_ObservableAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "observable_name": os.environ.get("TEST_GENERIC", "email@example.com"),
            "observable_classification": ObservableTypes.GENERIC.value,
        }


#### File Analyzer Test Cases ####


class EXEAnalyzersTestCase(_FileAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "file_name": "file.exe",
            "file_mimetype": "application/x-dosexec",
        }


class DLLAnalyzersTestCase(_FileAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "file_name": "file.dll",
            "file_mimetype": "application/x-dosexec",
        }


class ExcelAnalyzersTestCase(_FileAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "file_name": "document.xls",
            "file_mimetype": "application/vnd.ms-excel",
        }


class DocAnalyzersTestCase(_FileAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "file_name": "document.doc",
            "file_mimetype": "application/msword",
        }


class RtfAnalyzersTestCase(_FileAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "file_name": "document.rtf",
            "file_mimetype": "text/rtf",
        }


class PDFAnalyzersTestCase(_FileAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "file_name": "document.pdf",
            "file_mimetype": "application/pdf",
        }


class HTMLAnalyzersTestCase(_FileAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "file_name": "page.html",
            "file_mimetype": "text/html",
        }


class JSAnalyzersTestCase(_FileAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "file_name": "file.jse",
            "file_mimetype": "application/javascript",
        }


class APKAnalyzersTestCase(_FileAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "file_name": "sample.apk",
            "file_mimetype": "application/vnd.android.package-archive",
        }
