# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from django.core.files import File

from api_app.analyzers_manager.file_analyzers.boxjs_scan import BoxJS
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.models import Job
from tests import CustomTestCase


class BoxJSTestCase(CustomTestCase):
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
        analyzer_config = AnalyzerConfig.objects.get(name="BoxJS")
        boxjs_analyzer = BoxJS(analyzer_config)
        boxjs_analyzer.md5 = sample_md5
        boxjs_analyzer.filename = f"./test_files/{sample_name}"
        boxjs_analyzer.file_mimetype = sample_mimetype
        job = self._create_job(
            f"./test_files/{sample_name}", sample_mimetype, analyzer_config
        )
        boxjs_analyzer.start(job.id, {}, 1)
        return boxjs_analyzer.report.report

    @staticmethod
    def tearDown() -> None:
        Job.objects.all().delete()

    def test_urls(self):
        downloader_js_report = self._analyze(
            "downloader.js",
            "06423b5a0a4d4f444ea943e2bdaa5461",
            "application/javascript",
        )
        self.assertEqual(
            sorted(downloader_js_report["uris"]),
            sorted(
                [
                    "http://horus-protector.pro/c/s4.txt"
                    "http://horus-protector.pro/c/r4.txt"
                ]
            ),
        )
