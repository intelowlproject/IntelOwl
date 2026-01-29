# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.file_analyzers.doc_info import DocInfo
from api_app.models import Job
from tests import CustomTestCase


class DocInfoTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    @staticmethod
    def tearDown() -> None:
        Job.objects.all().delete()

    def test_follina(self):
        follina_docx_report = self._analyze_sample(
            "follina.doc",
            "15b691f0c5d627e71fed8a5d34fb0328",
            "application/msword",
            "Doc_Info",
            DocInfo,
        )
        self.assertEqual(
            follina_docx_report["follina"],
            ["mhtml:https://qaz.im/load/diy5ah/b6d42680-56fd-4f98-ae0e-ff81e3799df6!"],
        )

        follina2_docx_report = self._analyze_sample(
            "follina2.doc",
            "eb5e57e7db3af792b4c9e9f28525843b",
            "application/msword",
            "Doc_Info",
            DocInfo,
        )
        self.assertEqual(
            follina2_docx_report["follina"],
            ["http://13.234.135.58/loadingupdate.html!"],
        )

    def test_macro(self):
        document_doc_report = self._analyze_sample(
            "document.doc",
            "094268e03ab9e2e23f0d24554cb81a1b",
            "application/msword",
            "Doc_Info",
            DocInfo,
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
        cve_xls_report = self._analyze_sample(
            "cve.xls",
            "d5c0296562466d2f4a76a065bc3376e2",
            "application/excel",
            "Doc_Info",
            DocInfo,
        )
        self.assertEqual(
            cve_xls_report["extracted_CVEs"][0]["CVEs"],
            ["CVE-2017-0199", "CVE-2017-8570", "CVE-2017-8759", "CVE-2018-8174"],
        )

    def test_urls(self):
        downloader_docx_report = self._analyze_sample(
            "downloader.docx",
            "c35b7e980b618f8cf19c5a7a801c3e5b",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "Doc_Info",
            DocInfo,
        )
        self.assertEqual(
            downloader_docx_report["uris"],
            ["https://malware.document.test/testmalware.txt"],
        )
        urls1_xls_report = self._analyze_sample(
            "urls1.xls",
            "7facca44e3c764b946cb370de32168bd",
            "application/excel",
            "Doc_Info",
            DocInfo,
        )
        self.assertIn("https://kendallvilleglass.com/vers/ber.php", urls1_xls_report["uris"])
        urls2_xls_report = self._analyze_sample(
            "urls2.xls",
            "b4b3a2223765ac84c9b1b05dbf7c6503",
            "application/excel",
            "Doc_Info",
            DocInfo,
        )
        self.assertCountEqual(
            urls2_xls_report["uris"],
            [
                "http://190.14.37.178/",
                "http://185.183.96.67/",
                "http://185.250.148.213/",
            ],
        )
