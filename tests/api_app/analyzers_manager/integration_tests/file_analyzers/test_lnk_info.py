# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.file_analyzers.lnk_info import LnkInfo
from api_app.models import Job
from tests import CustomTestCase


class LnkInfoTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    @staticmethod
    def tearDown() -> None:
        Job.objects.all().delete()

    def test_urls(self):
        downloader_lnk_report = self._analyze_sample(
            "downloader.lnk",
            "4fa46e8663b40ca77dc70dbd952c84ef",
            "application/x-ms-shortcut",
            "Lnk_Info",
            LnkInfo,
        )
        self.assertEqual(
            downloader_lnk_report["uris"],
            ["https://vidstreemz.b-cdn.net/matodown"],
        )
