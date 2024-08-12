# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from django.core.files import File

from api_app.analyzers_manager.file_analyzers.strings_info import StringsInfo
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.models import Job
from tests import CustomTestCase


class StringsInfoTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    def _create_job(self, sample, mimetype, analyzer_config) -> Job:
        try:
            with open(sample, "rb") as f:
                _job = Job.objects.create(
                    is_sample=True,
                    file_name=sample,
                    file_mimetype=mimetype,
                    file=File(f),
                    user=self.superuser,
                )
                _job.analyzers_to_execute.set([analyzer_config])
                return _job
        except Exception as e:
            print(f"Error: {e}")

    def _analyze(self, sample_name, sample_md5, sample_mimetype):
        analyzer_config = AnalyzerConfig.objects.get(name="Strings_Info")
        analyzer_config.max_number_of_strings = 2000
        strings_info_analyzer = StringsInfo(analyzer_config)
        strings_info_analyzer.md5 = sample_md5
        strings_info_analyzer.filename = f"./tests/test_files/{sample_name}"
        strings_info_analyzer.file_mimetype = sample_mimetype
        job = self._create_job(
            f"./tests/test_files/{sample_name}", sample_mimetype, analyzer_config
        )
        strings_info_analyzer.start(job.id, {}, 1)
        return strings_info_analyzer.report.report

    @staticmethod
    def tearDown() -> None:
        Job.objects.all().delete()

    def test_urls(self):
        downloader_pdf_report = self._analyze(
            "downloader.pdf", "d7be84a4e07b0aadfffb12cbcbd668eb", "application/pdf"
        )
        # unfortunally the pdf uri syntax add an extra valid char in the strings: ")"
        # '/URI (https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe)>>>>
        # for this reason we check only if the url is present inside the list
        urls_to_check = "\t".join(downloader_pdf_report["uris"])
        self.assertTrue(
            "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe"
            in urls_to_check
        )
        self.assertTrue("https://it.lipsum.com/" in urls_to_check)
        self.assertTrue("https://it.lipsum.com/privacy" in urls_to_check)
