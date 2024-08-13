# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


import base64

from django.core.files import File

from api_app.analyzers_manager.file_analyzers.onenote import OneNoteInfo
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.models import Job
from tests import CustomTestCase


class OneNoteInfoTestCase(CustomTestCase):
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
        analyzer_config = AnalyzerConfig.objects.get(name="OneNote_Info")
        onenote_info_analyzer = OneNoteInfo(analyzer_config)
        onenote_info_analyzer.md5 = sample_md5
        onenote_info_analyzer.filename = f"test_files/{sample_name}"
        onenote_info_analyzer.file_mimetype = sample_mimetype
        job = self._create_job(
            f"test_files/{sample_name}", sample_mimetype, analyzer_config
        )
        onenote_info_analyzer.start(job.id, {}, 1)
        return onenote_info_analyzer.report.report

    @staticmethod
    def tearDown() -> None:
        Job.objects.all().delete()

    def test_urls(self):
        downloader_onenote_report = self._analyze(
            "downloader.one", "c35b7e980b618f8cf19c5a7a801c3e5b", "application/onenote"
        )
        self.assertEqual(len(downloader_onenote_report["stored_base64"]), 1)
        decoded = base64.b64decode(
            downloader_onenote_report["stored_base64"][0]
        ).decode()
        self.assertTrue("91.207.183.9" in decoded)
