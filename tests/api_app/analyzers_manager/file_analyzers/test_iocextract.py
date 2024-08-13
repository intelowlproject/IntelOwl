# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from django.core.files import File

from api_app.analyzers_manager.file_analyzers.iocextract import IocExtract
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.models import Job
from tests import CustomTestCase


class IocExtractTestCase(CustomTestCase):
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
        analyzer_config = AnalyzerConfig.objects.get(name="IocExtract")
        iocextract_analyzer = IocExtract(analyzer_config)
        iocextract_analyzer.md5 = sample_md5
        iocextract_analyzer.filename = f"test_files/{sample_name}"
        iocextract_analyzer.file_mimetype = sample_mimetype
        job = self._create_job(
            f"test_files/{sample_name}", sample_mimetype, analyzer_config
        )
        iocextract_analyzer.start(job.id, {}, 1)
        return iocextract_analyzer.report.report

    @staticmethod
    def tearDown() -> None:
        Job.objects.all().delete()

    def test_urls(self):
        textfile_txt_report = self._analyze(
            "textfile.txt",
            "f263b6951f3d25b165d060b7f5251d33",
            "text/plain",
        )
        self.assertIn(
            "https://evildomain.tld/mauris.get", textfile_txt_report["all_iocs"]
        )
        self.assertIn("1.1.1.1", textfile_txt_report["all_iocs"])
        self.assertIn(
            "5f423b7772a80f77438407c8b78ff305", textfile_txt_report["all_iocs"]
        )
        self.assertIn("suscipit-evilmail@gmail.com", textfile_txt_report["all_iocs"])
