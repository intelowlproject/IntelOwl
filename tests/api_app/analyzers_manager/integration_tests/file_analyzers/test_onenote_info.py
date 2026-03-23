# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


import base64

from api_app.analyzers_manager.file_analyzers.onenote import OneNoteInfo
from api_app.models import Job
from tests import CustomTestCase


class OneNoteInfoTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    @staticmethod
    def tearDown() -> None:
        Job.objects.all().delete()

    def test_urls(self):
        downloader_onenote_report = self._analyze_sample(
            "downloader.one",
            "c35b7e980b618f8cf19c5a7a801c3e5b",
            "application/onenote",
            "OneNote_Info",
            OneNoteInfo,
        )
        self.assertEqual(len(downloader_onenote_report["stored_base64"]), 1)
        decoded = base64.b64decode(downloader_onenote_report["stored_base64"][0]).decode()
        self.assertIn("91.207.183.9", decoded)
