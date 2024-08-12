# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from django.core.files import File

from api_app.analyzers_manager.file_analyzers.lnk_info import LnkInfo
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.models import Job
from tests import CustomTestCase


class LnkInfoTestCase(CustomTestCase):
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
        analyzer_config = AnalyzerConfig.objects.get(name="Lnk_Info")
        lnk_info_analyzer = LnkInfo(analyzer_config)
        lnk_info_analyzer.md5 = sample_md5
        lnk_info_analyzer.filename = f"./tests/test_files/{sample_name}"
        lnk_info_analyzer.file_mimetype = sample_mimetype
        job = self._create_job(
            f"./tests/test_files/{sample_name}", sample_mimetype, analyzer_config
        )
        lnk_info_analyzer.start(job.id, {}, 1)
        return lnk_info_analyzer.report.report

    @staticmethod
    def tearDown() -> None:
        Job.objects.all().delete()

    def test_urls(self):
        downloader_lnk_report = self._analyze(
            "downloader.lnk",
            "4fa46e8663b40ca77dc70dbd952c84ef",
            "application/x-ms-shortcut",
        )
        self.assertEqual(
            downloader_lnk_report["uris"],
            ["https://vidstreemz.b-cdn.net/matodown"],
        )
