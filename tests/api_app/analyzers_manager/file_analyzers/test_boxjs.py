# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest import skipIf

from api_app.analyzers_manager.file_analyzers.boxjs_scan import BoxJS
from api_app.models import Job
from tests import CustomTestCase


class BoxJSTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    @staticmethod
    def tearDown() -> None:
        Job.objects.all().delete()

    @skipIf(
        not BoxJS(None).health_check(), "malware tools analyzer container not active"
    )
    def test_urls(self):
        downloader_js_report = self._analyze_sample(
            "downloader.js",
            "06423b5a0a4d4f444ea943e2bdaa5461",
            "application/javascript",
            "BoxJS",
            BoxJS,
        )
        self.assertCountEqual(
            downloader_js_report["uris"],
            [
                "http://horus-protector.pro/c/s2.txt",
                "http://horus-protector.pro/c/r2.txt",
            ],
        )
