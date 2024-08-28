# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from api_app.analyzers_manager.file_analyzers.pdf_info import PDFInfo
from api_app.models import Job
from tests import CustomTestCase


class PDFInfoTestCase(CustomTestCase):
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
            "PDF_Info",
            PDFInfo,
        )
        self.assertCountEqual(
            downloader_pdf_report["uris"],
            [
                "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe",
                "https://it.lipsum.com/",
                "https://it.lipsum.com/privacy",
            ],
        )
