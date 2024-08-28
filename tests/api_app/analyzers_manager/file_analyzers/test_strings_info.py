# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.file_analyzers.strings_info import StringsInfo
from api_app.models import Job
from tests import CustomTestCase


class StringsInfoTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    @staticmethod
    def tearDown() -> None:
        Job.objects.all().delete()

    def test_urls(self):
        downloader_pdf_report = self._analyze_sample(
            "downloader.pdf",
            "d7be84a4e07b0aadfffb12cbcbd668eb",
            "application/pdf",
            "Strings_Info",
            StringsInfo,
        )
        # unfortunally the pdf uri syntax add an extra valid char in the strings: ")"
        # '/URI (https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe)>>>>
        # for this reason we check only if the url is present inside the joined list
        urls_to_check = "\t".join(downloader_pdf_report["uris"])
        self.assertIn(
            "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe",
            urls_to_check,
        )
        self.assertIn("https://it.lipsum.com/", urls_to_check)
        self.assertIn("https://it.lipsum.com/privacy", urls_to_check)
