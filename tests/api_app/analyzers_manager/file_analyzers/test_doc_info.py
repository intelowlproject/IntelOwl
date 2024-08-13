# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from django.core.files import File

from api_app.analyzers_manager.file_analyzers.doc_info import DocInfo
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.models import Job
from tests import CustomTestCase


class DocInfoTestCase(CustomTestCase):
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
        analyzer_config = AnalyzerConfig.objects.get(name="Doc_Info")
        doc_info_analyzer = DocInfo(analyzer_config)
        doc_info_analyzer.md5 = sample_md5
        doc_info_analyzer.filename = f"test_files/{sample_name}"
        doc_info_analyzer.file_mimetype = sample_mimetype
        job = self._create_job(
            f"test_files/{sample_name}", sample_mimetype, analyzer_config
        )
        doc_info_analyzer.start(job.id, {}, 1)
        return doc_info_analyzer.report.report

    @staticmethod
    def tearDown() -> None:
        Job.objects.all().delete()

    def test_follina(self):
        follina_docx_report = self._analyze(
            "follina.doc",
            "15b691f0c5d627e71fed8a5d34fb0328",
            "application/msword",
        )
        self.assertEqual(
            follina_docx_report["follina"],
            ["mhtml:https://qaz.im/load/diy5ah/b6d42680-56fd-4f98-ae0e-ff81e3799df6!"],
        )

        follina2_docx_report = self._analyze(
            "follina2.doc",
            "eb5e57e7db3af792b4c9e9f28525843b",
            "application/msword",
        )
        self.assertEqual(
            follina2_docx_report["follina"],
            ["http://13.234.135.58/loadingupdate.html!"],
        )

    def test_macro(self):
        document_doc_report = self._analyze(
            "document.doc", "094268e03ab9e2e23f0d24554cb81a1b", "application/msword"
        )
        analyzed_macros = document_doc_report["olevba"]["analyze_macro"]
        keywords = [macro["keyword"] for macro in analyzed_macros]
        self.assertIn("AutoOpen", keywords)
        self.assertIn("Shell", keywords)
        self.assertIn("WScript.Shell", keywords)
        self.assertIn("Run", keywords)
        self.assertIn("powershell", keywords)
        self.assertIn("Call", keywords)
        self.assertIn("CreateObject", keywords)
        self.assertIn("Exec", keywords)
        self.assertIn("Hex Strings", keywords)

    def test_cve(self):
        cve_xls_report = self._analyze(
            "cve.xls", "d5c0296562466d2f4a76a065bc3376e2", "application/excel"
        )
        self.assertEqual(
            cve_xls_report["extracted_CVEs"][0]["CVEs"],
            ["CVE-2017-0199", "CVE-2017-8570", "CVE-2017-8759", "CVE-2018-8174"],
        )

    def test_urls(self):
        downloader_docx_report = self._analyze(
            "downloader.docx",
            "c35b7e980b618f8cf19c5a7a801c3e5b",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        self.assertEqual(
            downloader_docx_report["uris"],
            ["https://malware.document.test/testmalware.txt"],
        )
        urls1_xls_report = self._analyze(
            "urls1.xls", "7facca44e3c764b946cb370de32168bd", "application/excel"
        )
        self.assertIn(
            "https://kendallvilleglass.com/vers/ber.php", urls1_xls_report["uris"]
        )
        urls2_xls_report = self._analyze(
            "urls2.xls", "b4b3a2223765ac84c9b1b05dbf7c6503", "application/excel"
        )
        self.assertCountEqual(
            urls2_xls_report["uris"],
            [
                "http://190.14.37.178/",
                "http://185.183.96.67/",
                "http://185.250.148.213/",
            ],
        )
