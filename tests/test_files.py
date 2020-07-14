import hashlib
import logging

from django.core.files import File
from django.test import TestCase
from unittest.mock import patch, MagicMock

from api_app.script_analyzers import general
from api_app.script_analyzers.file_analyzers import (
    file_info,
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
)
from api_app.script_analyzers.observable_analyzers import vt3_get

from api_app.models import Job
from api_app.script_analyzers.file_analyzers import signature_info
from .test_api import MockResponse

from intel_owl import settings

logger = logging.getLogger(__name__)
# disable logging library for travis
if settings.DISABLE_LOGGING_TEST:
    logging.disable(logging.CRITICAL)


# it is optional to mock requests
def mock_connections(decorator):
    return decorator if settings.MOCK_CONNECTIONS else lambda x: x


def mocked_requests(*args, **kwargs):
    return MockResponse({}, 200)


def mocked_vt_get(*args, **kwargs):
    return MockResponse({"data": {"attributes": {"status": "completed"}}}, 200)


def mocked_vt_post(*args, **kwargs):
    return MockResponse({"scan_id": "scan_id_test", "data": {"id": "id_test"}}, 200)


def mocked_intezer(*args, **kwargs):
    return MockResponse({}, 201)


def mocked_cuckoo_get(*args, **kwargs):
    return MockResponse({"task": {"status": "reported"}}, 200)


def mocked_peframe_get(*args, **kwargs):
    return MockResponse({"key": "test", "status": "success", "report": {}}, 200,)


def mocked_peframe_post(*args, **kwargs):
    return MockResponse({"key": "test", "status": "running"}, 202)


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
        self.filepath, self.filename = general.get_filepath_filename(self.job_id)
        self.md5 = test_job.md5

    def test_fileinfo_exe(self):
        report = file_info.run(
            "File_Info", self.job_id, self.filepath, self.filename, self.md5, {}
        )
        self.assertEqual(report.get("success", False), True)

    def test_stringsinfo_ml_exe(self):
        report = strings_info.run(
            "Strings_Info_ML",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            {"rank_strings": True},
        )
        self.assertEqual(report.get("success", False), True)

    def test_stringsinfo_classic_exe(self):
        report = strings_info.run(
            "Strings_Info_Classic",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_peinfo_exe(self):
        report = pe_info.run(
            "PE_Info", self.job_id, self.filepath, self.filename, self.md5, {}
        )
        self.assertEqual(report.get("success", False), True)

    def test_signatureinfo_exe(self):
        report = signature_info.run(
            "Signature_Info", self.job_id, self.filepath, self.filename, self.md5, {}
        )
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.get", side_effect=mocked_vt_get))
    @mock_connections(patch("requests.post", side_effect=mocked_vt_post))
    def test_vtscan_exe(self, mock_get=None, mock_post=None):
        additional_params = {"wait_for_scan_anyway": True, "max_tries": 1}
        report = vt2_scan.run(
            "VT_v2_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        )
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
        report = intezer_scan.run(
            "Intezer_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        )
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.Session.get", side_effect=mocked_cuckoo_get))
    @mock_connections(patch("requests.Session.post", side_effect=mocked_requests))
    def test_cuckoo_exe(self, mock_get=None, mock_post=None):
        additional_params = {"max_poll_tries": 1, "max_post_tries": 1}
        report = cuckoo_scan.run(
            "Cuckoo_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        )
        self.assertEqual(report.get("success", False), True)

    def test_yara_exe(self):
        additional_params = {
            "directories_with_rules": [
                "/opt/deploy/yara/rules",
                "/opt/deploy/yara/intezer_rules",
                "/opt/deploy/yara/mcafee_rules",
                "/opt/deploy/yara/signature-base/yara",
            ]
        }
        report = yara_scan.run(
            "Yara_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        )
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.get", side_effect=mocked_vt_get))
    @mock_connections(patch("requests.post", side_effect=mocked_vt_post))
    def test_vt3_scan_exe(self, mock_get=None, mock_post=None):
        additional_params = {"max_tries": 1}
        report = vt3_scan.run(
            "VT_v3_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        )
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.get", side_effect=mocked_requests))
    @mock_connections(patch("requests.post", side_effect=mocked_requests))
    def test_vt3_get_and_scan_exe(self, mock_get=None, mock_post=None):
        additional_params = {"max_tries": 1, "force_active_scan": True}
        report = vt3_get.run(
            "VT_v3_Get_And_Scan", self.job_id, self.md5, "hash", additional_params
        )
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.get", side_effect=mocked_peframe_get))
    @mock_connections(patch("requests.post", side_effect=mocked_peframe_post))
    def test_peframe_scan_file(self, mock_get=None, mock_post=None):
        additional_params = {"max_tries": 10}
        report = peframe.run(
            "PEframe_Scan_File",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        )
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
        self.filepath, self.filename = general.get_filepath_filename(self.job_id)
        self.md5 = test_job.md5

    def test_fileinfo_dll(self):
        report = file_info.run(
            "File_Info", self.job_id, self.filepath, self.filename, self.md5, {}
        )
        self.assertEqual(report.get("success", False), True)

    def test_peinfo_dll(self):
        report = pe_info.run(
            "PE_Info", self.job_id, self.filepath, self.filename, self.md5, {}
        )
        self.assertEqual(report.get("success", False), True)


class FileAnalyzersDocTests(TestCase):
    def setUp(self):
        params = {
            "source": "test",
            "is_sample": True,
            "file_mimetype": "application/msword",
            "force_privacy": False,
            "analyzers_requested": ["test"],
        }
        filename = "document.doc"
        test_job = _generate_test_job_with_file(params, filename)
        self.job_id = test_job.id
        self.filepath, self.filename = general.get_filepath_filename(self.job_id)
        self.md5 = test_job.md5

    def test_docinfo(self):
        report = doc_info.run(
            "Doc_Info", self.job_id, self.filepath, self.filename, self.md5, {}
        )
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.get", side_effect=mocked_peframe_get))
    @mock_connections(patch("requests.post", side_effect=mocked_peframe_post))
    def test_peframe_scan_file(self, mock_get=None, mock_post=None):
        additional_params = {"max_tries": 1}
        report = peframe.run(
            "PEframe_Scan_File",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        )
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
        self.filepath, self.filename = general.get_filepath_filename(self.job_id)
        self.md5 = test_job.md5

    def test_rtfinfo(self):
        report = rtf_info.run(
            "Rtf_Info", self.job_id, self.filepath, self.filename, self.md5, {}
        )
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
        self.filepath, self.filename = general.get_filepath_filename(self.job_id)
        self.md5 = test_job.md5

    def test_pdfinfo(self):
        report = pdf_info.run(
            "PDF_Info", self.job_id, self.filepath, self.filename, self.md5, {}
        )
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
