# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.file_analyzers.iocextract import IocExtract
from api_app.models import Job
from tests import CustomTestCase


class IocExtractTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    @staticmethod
    def tearDown() -> None:
        Job.objects.all().delete()

    def test_urls(self):
        textfile_txt_report = self._analyze_sample(
            "textfile.txt",
            "f263b6951f3d25b165d060b7f5251d33",
            "text/plain",
            "IocExtract",
            IocExtract,
        )
        self.assertIn("https://evildomain.tld/mauris.get", textfile_txt_report["all_iocs"])
        self.assertIn("1.1.1.1", textfile_txt_report["all_iocs"])
        self.assertIn("5f423b7772a80f77438407c8b78ff305", textfile_txt_report["all_iocs"])
        self.assertIn("suscipit-evilmail@gmail.com", textfile_txt_report["all_iocs"])
