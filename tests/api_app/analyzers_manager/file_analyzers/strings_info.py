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
        urls2_xls_report = self._analyze(
            "urls2.xls", "b4b3a2223765ac84c9b1b05dbf7c6503", "application/excel"
        )
        print(f"{urls2_xls_report=}")
        self.assertEqual(
            sorted(urls2_xls_report["uris"]),
            sorted(
                [
                    "http://190.14.37.178/",
                    "http://185.183.96.67/",
                    "http://185.250.148.213/",
                ]
            ),
        )
