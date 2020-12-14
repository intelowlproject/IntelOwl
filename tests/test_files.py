import hashlib
import logging

from django.core.files import File
from django.test import TestCase
from unittest.mock import patch, MagicMock

from api_app.script_analyzers import utils
from api_app.script_analyzers.file_analyzers import (
    file_info,
    signature_info,
    speakeasy_emulation,
    pe_info,
    doc_info,
    pdf_info,
    vt2_scan,
    intezer_scan,
    cuckoo_scan,
    yara_scan,
    vt3_scan,
    strings_info,
    rtf_info,
    peframe,
    thug_file,
    capa_info,
    boxjs_scan,
    apkid,
    quark_engine,
    unpac_me,
    xlm_macro_deobfuscator,
    triage_scan,
    floss,
    manalyze,
)
from api_app.script_analyzers.observable_analyzers import vt3_get

from api_app.models import Job
from .mock_utils import (
    MockResponse,
    mocked_requests,
    mocked_docker_analyzer_get,
    mocked_docker_analyzer_post,
)

from intel_owl import settings

# disable logging library for Continuous Integration
if settings.DISABLE_LOGGING_TEST:
    logging.disable(logging.CRITICAL)


# it is optional to mock requests
def mock_connections(decorator):
    return decorator if settings.MOCK_CONNECTIONS else lambda x: x


def mocked_unpacme_post(*args, **kwargs):
    return MockResponse({"id": "test"}, 200)


def mocked_unpacme_get(*args, **kwargs):
    return MockResponse({"id": "test", "status": "complete"}, 200)


def mocked_vt_get(*args, **kwargs):
    return MockResponse({"data": {"attributes": {"status": "completed"}}}, 200)


def mocked_vt_post(*args, **kwargs):
    return MockResponse({"scan_id": "scan_id_test", "data": {"id": "id_test"}}, 200)


def mocked_intezer(*args, **kwargs):
    return MockResponse({}, 201)


def mocked_cuckoo_get(*args, **kwargs):
    return MockResponse({"task": {"status": "reported"}}, 200)


def mocked_triage_get(*args, **kwargs):
    return MockResponse({"tasks": {"task_1": {}, "task_2": {}}}, 200)


def mocked_triage_post(*args, **kwargs):
    return MockResponse({"id": "sample_id", "status": "pending"}, 200)


class FileAnalyzersEXETests(TestCase):
    def setUp(self):
        params = {
            "source": "test",
            "is_sample": True,
            "file_mimetype": "application/x-dosexec",
            "force_privacy": False,
            "analyzers_requested": ["test"],
        }
        filename = "file.exe"
        test_job = _generate_test_job_with_file(params, filename)
        self.job_id = test_job.id
        self.filepath, self.filename = utils.get_filepath_filename(self.job_id)
        self.md5 = test_job.md5

    def test_fileinfo_exe(self):
        report = file_info.FileInfo(
            "File_Info", self.job_id, self.filepath, self.filename, self.md5, {}
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.get", side_effect=mocked_docker_analyzer_get))
    @mock_connections(patch("requests.post", side_effect=mocked_docker_analyzer_post))
    def test_stringsinfo_ml_exe(self, mock_get=None, mock_post=None):
        report = strings_info.StringsInfo(
            "Strings_Info_ML",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            {"rank_strings": True},
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.get", side_effect=mocked_docker_analyzer_get))
    @mock_connections(patch("requests.post", side_effect=mocked_docker_analyzer_post))
    def test_stringsinfo_classic_exe(self, mock_get=None, mock_post=None):
        report = strings_info.StringsInfo(
            "Strings_Info_Classic",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_peinfo_exe(self):
        report = pe_info.PEInfo(
            "PE_Info", self.job_id, self.filepath, self.filename, self.md5, {}
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_signatureinfo_exe(self):
        report = signature_info.SignatureInfo(
            "Signature_Info", self.job_id, self.filepath, self.filename, self.md5, {}
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_speakeasy_exe(self):
        report = speakeasy_emulation.SpeakEasy(
            "Speakeasy", self.job_id, self.filepath, self.filename, self.md5, {}
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.get", side_effect=mocked_vt_get))
    @mock_connections(patch("requests.post", side_effect=mocked_vt_post))
    def test_vtscan_exe(self, mock_get=None, mock_post=None):
        additional_params = {"wait_for_scan_anyway": True, "max_tries": 1}
        report = vt2_scan.VirusTotalv2ScanFile(
            "VT_v2_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.Session.get", side_effect=mocked_requests))
    @mock_connections(patch("requests.Session.post", side_effect=mocked_intezer))
    @mock_connections(
        patch(
            "api_app.script_analyzers.file_analyzers.intezer_scan._get_access_token",
            MagicMock(return_value="tokentest"),
        )
    )
    def test_intezer_exe(self, mock_get=None, mock_post=None, mock_token=None):
        additional_params = {"max_tries": 1, "is_test": True}
        report = intezer_scan.IntezerScan(
            "Intezer_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.Session.get", side_effect=mocked_cuckoo_get))
    @mock_connections(patch("requests.Session.post", side_effect=mocked_requests))
    def test_cuckoo_exe(self, mock_get=None, mock_post=None):
        additional_params = {"max_poll_tries": 1, "max_post_tries": 1}
        report = cuckoo_scan.CuckooAnalysis(
            "Cuckoo_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_yara_mcafee(self):
        additional_params = {
            "directories_with_rules": [
                "/opt/deploy/yara/mcafee_rules/APT",
                "/opt/deploy/yara/mcafee_rules/RAT",
                "/opt/deploy/yara/mcafee_rules/malware",
                "/opt/deploy/yara/mcafee_rules/miners",
                "/opt/deploy/yara/mcafee_rules/ransomware",
                "/opt/deploy/yara/mcafee_rules/stealer",
            ]
        }
        report = yara_scan.YaraScan(
            "Yara_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_yara_daily_ioc(self):
        additional_params = {
            "directories_with_rules": [
                "/opt/deploy/yara/daily_ioc_rules",
            ],
            "recursive": True,
        }
        report = yara_scan.YaraScan(
            "Yara_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_yara_stratosphere(self):
        additional_params = {
            "directories_with_rules": [
                "/opt/deploy/yara/stratosphere_rules/malware",
                "/opt/deploy/yara/stratosphere_rules/protocols",
            ]
        }
        report = yara_scan.YaraScan(
            "Yara_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_yara_inquest(self):
        additional_params = {
            "directories_with_rules": [
                "/opt/deploy/yara/inquest_rules",
                "/opt/deploy/yara/inquest_rules/labs.inquest.net",
            ]
        }
        report = yara_scan.YaraScan(
            "Yara_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_yara_intezer(self):
        additional_params = {
            "directories_with_rules": [
                "/opt/deploy/yara/intezer_rules",
            ]
        }
        report = yara_scan.YaraScan(
            "Yara_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_yara_reversinglabs(self):
        additional_params = {
            "directories_with_rules": ["/opt/deploy/yara/reversinglabs_rules/yara"],
            "recursive": True,
        }
        report = yara_scan.YaraScan(
            "Yara_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_yara_samir(self):
        additional_params = {
            "directories_with_rules": [
                "/opt/deploy/yara/samir_rules",
            ]
        }
        report = yara_scan.YaraScan(
            "Yara_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_yara_fireeye(self):
        additional_params = {
            "directories_with_rules": [
                "/opt/deploy/yara/fireeye_rules/rules",
            ],
            "recursive": True,
        }
        report = yara_scan.YaraScan(
            "Yara_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_yara_florian(self):
        additional_params = {
            "directories_with_rules": [
                "/opt/deploy/yara/signature-base/yara",
            ]
        }
        report = yara_scan.YaraScan(
            "Yara_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_yara_community(self):
        additional_params = {
            "directories_with_rules": [
                "/opt/deploy/yara/rules",
            ]
        }
        report = yara_scan.YaraScan(
            "Yara_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.get", side_effect=mocked_unpacme_get))
    @mock_connections(patch("requests.post", side_effect=mocked_unpacme_post))
    def test_unpacme_exe(self, mock_get=None, mock_post=None):
        report = unpac_me.UnpacMe(
            "UnpacMe_EXE_Unpacker",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.get", side_effect=mocked_vt_get))
    @mock_connections(patch("requests.post", side_effect=mocked_vt_post))
    def test_vt3_scan_exe(self, mock_get=None, mock_post=None):
        additional_params = {"max_tries": 1}
        report = vt3_scan.VirusTotalv3ScanFile(
            "VT_v3_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.get", side_effect=mocked_requests))
    @mock_connections(patch("requests.post", side_effect=mocked_requests))
    def test_vt3_get_and_scan_exe(self, mock_get=None, mock_post=None):
        additional_params = {"max_tries": 1, "force_active_scan": True}
        report = vt3_get.VirusTotalv3(
            "VT_v3_Get_And_Scan", self.job_id, self.md5, "hash", additional_params
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.get", side_effect=mocked_docker_analyzer_get))
    @mock_connections(patch("requests.post", side_effect=mocked_docker_analyzer_post))
    def test_peframe_scan_file(self, mock_get=None, mock_post=None):
        additional_params = {"max_tries": 1}
        report = peframe.PEframe(
            "PEframe_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.get", side_effect=mocked_docker_analyzer_get))
    @mock_connections(patch("requests.post", side_effect=mocked_docker_analyzer_post))
    def test_capa_scan_file(self, mock_get=None, mock_post=None):
        report = capa_info.CapaInfo(
            "Capa_Info",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.get", side_effect=mocked_triage_get))
    @mock_connections(patch("requests.post", side_effect=mocked_triage_post))
    def test_triage_scan(self, mock_get=None, mock_post=None):
        report = triage_scan.TriageScanFile(
            "Triage_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.get", side_effect=mocked_docker_analyzer_get))
    @mock_connections(patch("requests.post", side_effect=mocked_docker_analyzer_post))
    def test_floss(self, mock_get=None, mock_post=None):
        report = floss.Floss(
            "Floss",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.get", side_effect=mocked_docker_analyzer_get))
    @mock_connections(patch("requests.post", side_effect=mocked_docker_analyzer_post))
    def test_manalyze(self, mock_get=None, mock_post=None):
        report = manalyze.Manalyze(
            "Manalyze",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)


class FileAnalyzersDLLTests(TestCase):
    def setUp(self):
        params = {
            "source": "test",
            "is_sample": True,
            "file_mimetype": "application/x-dosexec",
            "force_privacy": False,
            "analyzers_requested": ["test"],
        }
        filename = "file.dll"
        test_job = _generate_test_job_with_file(params, filename)
        self.job_id = test_job.id
        self.filepath, self.filename = utils.get_filepath_filename(self.job_id)
        self.md5 = test_job.md5

    def test_fileinfo_dll(self):
        report = file_info.FileInfo(
            "File_Info", self.job_id, self.filepath, self.filename, self.md5, {}
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_peinfo_dll(self):
        report = pe_info.PEInfo(
            "PE_Info", self.job_id, self.filepath, self.filename, self.md5, {}
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_speakeasy_dll(self):
        report = speakeasy_emulation.SpeakEasy(
            "Speakeasy", self.job_id, self.filepath, self.filename, self.md5, {}
        ).start()
        self.assertEqual(report.get("success", False), True)


class FileAnalyzersExcelTests(TestCase):
    def setUp(self):
        params = {
            "source": "test",
            "is_sample": True,
            "file_mimetype": "application/vnd.ms-excel",
            "force_privacy": False,
            "analyzers_requested": ["test"],
        }
        filename = "document.xls"
        test_job = _generate_test_job_with_file(params, filename)
        self.job_id = test_job.id
        self.filepath, self.filename = utils.get_filepath_filename(self.job_id)
        self.runtime_configuration = test_job.runtime_configuration
        self.md5 = test_job.md5

    def test_xlm_macro_deobfuscator_excel(self):
        report = xlm_macro_deobfuscator.XlmMacroDeobfuscator(
            "Xlm_Macro_Deobfuscator",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)


class FileAnalyzersDocTests(TestCase):
    def setUp(self):
        params = {
            "source": "test",
            "is_sample": True,
            "file_mimetype": "application/msword",
            "force_privacy": False,
            "analyzers_requested": ["test"],
            "runtime_configuration": {
                "Doc_Info_Experimental": {
                    "additional_passwords_to_check": ["testpassword"]
                }
            },
        }
        filename = "document.doc"
        test_job = _generate_test_job_with_file(params, filename)
        self.job_id = test_job.id
        self.filepath, self.filename = utils.get_filepath_filename(self.job_id)
        self.runtime_configuration = test_job.runtime_configuration
        self.md5 = test_job.md5

    def test_docinfo(self):
        report = doc_info.DocInfo(
            "Doc_Info", self.job_id, self.filepath, self.filename, self.md5, {}
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_docinfo_experimental(self):
        analyzer_name = "Doc_Info_Experimental"
        additional_params = {"experimental": True}
        utils.adjust_analyzer_config(
            self.runtime_configuration, additional_params, analyzer_name
        )
        report = doc_info.DocInfo(
            analyzer_name,
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.get", side_effect=mocked_docker_analyzer_get))
    @mock_connections(patch("requests.post", side_effect=mocked_docker_analyzer_post))
    def test_peframe_scan_file(self, mock_get=None, mock_post=None):
        additional_params = {"max_tries": 1}
        report = peframe.PEframe(
            "PEframe_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        ).start()
        self.assertEqual(report.get("success", False), True)


class FileAnalyzersRtfTests(TestCase):
    def setUp(self):
        params = {
            "source": "test",
            "is_sample": True,
            "file_mimetype": "text/rtf",
            "force_privacy": False,
            "analyzers_requested": ["test"],
        }
        filename = "document.rtf"
        test_job = _generate_test_job_with_file(params, filename)
        self.job_id = test_job.id
        self.filepath, self.filename = utils.get_filepath_filename(self.job_id)
        self.md5 = test_job.md5

    def test_rtfinfo(self):
        report = rtf_info.RTFInfo(
            "Rtf_Info", self.job_id, self.filepath, self.filename, self.md5, {}
        ).start()
        self.assertEqual(report.get("success", False), True)


class FileAnalyzersPDFTests(TestCase):
    def setUp(self):
        params = {
            "source": "test",
            "is_sample": True,
            "file_mimetype": "application/pdf",
            "force_privacy": False,
            "analyzers_requested": ["test"],
        }
        filename = "document.pdf"
        test_job = _generate_test_job_with_file(params, filename)
        self.job_id = test_job.id
        self.filepath, self.filename = utils.get_filepath_filename(self.job_id)
        self.md5 = test_job.md5

    def test_pdfinfo(self):
        report = pdf_info.PDFInfo(
            "PDF_Info", self.job_id, self.filepath, self.filename, self.md5, {}
        ).start()
        self.assertEqual(report.get("success", False), True)


class FileAnalyzersHTMLTests(TestCase):
    def setUp(self):
        params = {
            "source": "test",
            "is_sample": True,
            "file_mimetype": "text/html",
            "force_privacy": False,
            "analyzers_requested": ["test"],
        }
        filename = "page.html"
        test_job = _generate_test_job_with_file(params, filename)
        self.job_id = test_job.id
        self.filepath, self.filename = utils.get_filepath_filename(self.job_id)
        self.md5 = test_job.md5

    @mock_connections(patch("requests.get", side_effect=mocked_docker_analyzer_get))
    @mock_connections(patch("requests.post", side_effect=mocked_docker_analyzer_post))
    def test_thug_html(self, mock_get=None, mock_post=None):
        report = thug_file.ThugFile(
            "Thug_HTML_Info",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)


class FileAnalyzersJSTests(TestCase):
    def setUp(self):
        params = {
            "source": "test",
            "is_sample": True,
            "file_mimetype": "application/javascript",
            "force_privacy": False,
            "analyzers_requested": ["test"],
        }
        filename = "file.jse"
        test_job = _generate_test_job_with_file(params, filename)
        self.job_id = test_job.id
        self.filepath, self.filename = utils.get_filepath_filename(self.job_id)
        self.md5 = test_job.md5

    @mock_connections(patch("requests.get", side_effect=mocked_docker_analyzer_get))
    @mock_connections(patch("requests.post", side_effect=mocked_docker_analyzer_post))
    def test_boxjs(self, mock_get=None, mock_post=None):
        report = boxjs_scan.BoxJS(
            "BoxJS_Scan_JavaScript",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)


class FileAnalyzersAPKTests(TestCase):
    def setUp(self):
        params = {
            "source": "test",
            "is_sample": True,
            "file_mimetype": "application/vnd.android.package-archive",
            "force_privacy": False,
            "analyzers_requested": ["test"],
        }
        filename = "sample.apk"
        test_job = _generate_test_job_with_file(params, filename)
        self.job_id = test_job.id
        self.filepath, self.filename = utils.get_filepath_filename(self.job_id)
        self.md5 = test_job.md5

    @mock_connections(patch("requests.get", side_effect=mocked_docker_analyzer_get))
    @mock_connections(patch("requests.post", side_effect=mocked_docker_analyzer_post))
    def test_apkid(self, mock_get=None, mock_post=None):
        report = apkid.APKiD(
            "APKiD_Scan_APK_DEX_JAR",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_quark_engine(self, mock_get=None, mock_post=None):
        report = quark_engine.QuarkEngine(
            "Quark_Engine_APK",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)


def _generate_test_job_with_file(params, filename):
    test_file = f"{settings.PROJECT_LOCATION}/test_files/{filename}"
    with open(test_file, "rb") as f:
        django_file = File(f)
        params["file"] = django_file
        params["md5"] = hashlib.md5(django_file.file.read()).hexdigest()
        test_job = Job(**params)
        test_job.save()
    return test_job
