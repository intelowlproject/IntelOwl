import hashlib
import logging

from django.core.files import File
from django.test import TestCase
from unittest import skipIf

from api_app.script_analyzers import general
from api_app.script_analyzers.file_analyzers import file_info, pe_info, doc_info, pdf_info, vt2_scan, intezer_scan, \
    cuckoo_scan, yara_scan, vt3_scan, strings_info, rtf_info
from api_app.script_analyzers.observable_analyzers import vt3_get

from api_app.models import Job
from api_app.script_analyzers.file_analyzers import signature_info

from intel_owl import settings

logger = logging.getLogger(__name__)
# disable logging library for travis
if settings.TRAVIS_TEST:
    logging.disable(logging.CRITICAL)


class FileAnalyzersEXETests(TestCase):

    def setUp(self):
        params = {
            "source": "test",
            "is_sample": True,
            "file_mimetype": "application/x-dosexec",
            "force_privacy": False,
            "analyzers_requested": ["test"]
        }
        filename = "file.exe"
        test_job = _generate_test_job_with_file(params, filename)
        self.job_id = test_job.id
        self.filepath, self.filename = general.get_filepath_filename(self.job_id, logger)
        self.md5 = test_job.md5

    def test_fileinfo_exe(self):
        report = file_info.run("File_Info", self.job_id, self.filepath, self.filename, self.md5, {})
        self.assertEqual(report.get('success', False), True)

    def test_stringsinfo_ml_exe(self):
        report = strings_info.run("Strings_Info_ML", self.job_id, self.filepath, self.filename, self.md5,
                                  {"rank_strings": True})
        self.assertEqual(report.get('success', False), True)

    def test_stringsinfo_classic_exe(self):
        report = strings_info.run("Strings_Info_Classic", self.job_id, self.filepath, self.filename, self.md5, {})
        self.assertEqual(report.get('success', False), True)

    def test_peinfo_exe(self):
        report = pe_info.run("PE_Info", self.job_id, self.filepath, self.filename, self.md5, {})
        self.assertEqual(report.get('success', False), True)

    def test_signatureinfo_exe(self):
        report = signature_info.run("Signature_Info", self.job_id, self.filepath, self.filename, self.md5, {})
        self.assertEqual(report.get('success', False), True)

    def test_vtscan_exe(self):
        additional_params = {'wait_for_scan_anyway': True}
        report = vt2_scan.run("VT_v2_Scan", self.job_id, self.filepath, self.filename, self.md5, additional_params)
        self.assertEqual(report.get('success', False), True)

    def test_intezer_exe(self):
        additional_params = {'max_tries': 1, 'is_test': True}
        report = intezer_scan.run("Intezer_Scan", self.job_id, self.filepath, self.filename, self.md5, additional_params)
        self.assertEqual(report.get('success', False), True)

    @skipIf(settings.TRAVIS_TEST, "cuckoo instance missing")
    def test_cuckoo_exe(self):
        report = cuckoo_scan.run("Cuckoo_Scan", self.job_id, self.filepath, self.filename, self.md5, {})
        self.assertEqual(report.get('success', False), True)

    def test_yara_exe(self):
        additional_params = {"directories_with_rules": ["/opt/deploy/yara/rules",
                                                        "/opt/deploy/yara/yara-rules",
                                                        "/opt/deploy/yara/signature-base/yara"]}
        report = yara_scan.run("Yara_Scan", self.job_id, self.filepath, self.filename, self.md5, additional_params)
        self.assertEqual(report.get('success', False), True)

    def test_vt3_scan_exe(self):
        report = vt3_scan.run("VT_v3_Scan", self.job_id, self.filepath, self.filename, self.md5, {})
        self.assertEqual(report.get('success', False), True)

    def test_vt3_get_and_scan_exe(self):
        report = vt3_get.run("VT_v3_Get_And_Scan", self.job_id, self.md5, "hash", {'force_active_scan': True})
        self.assertEqual(report.get('success', False), True)


class FileAnalyzersDLLTests(TestCase):

    def setUp(self):
        params = {
            "source": "test",
            "is_sample": True,
            "file_mimetype": "application/x-dosexec",
            "force_privacy": False,
            "analyzers_requested": ["test"]
        }
        filename = "file.dll"
        test_job = _generate_test_job_with_file(params, filename)
        self.job_id = test_job.id
        self.filepath, self.filename = general.get_filepath_filename(self.job_id, logger)
        self.md5 = test_job.md5

    @skipIf(settings.TRAVIS_TEST, "dll check not required for travis")
    def test_fileinfo_dll(self):
        report = file_info.run("File_Info", self.job_id, self.filepath, self.filename, self.md5, {})
        self.assertEqual(report.get('success', False), True)

    @skipIf(settings.TRAVIS_TEST, "dll check not required for travis")
    def test_peinfo_dll(self):
        report = pe_info.run("PE_Info", self.job_id, self.filepath, self.filename, self.md5, {})
        self.assertEqual(report.get('success', False), True)


class FileAnalyzersDocTests(TestCase):

    def setUp(self):
        params = {
            "source": "test",
            "is_sample": True,
            "file_mimetype": "application/msword",
            "force_privacy": False,
            "analyzers_requested": ["test"]
        }
        filename = "document.doc"
        test_job = _generate_test_job_with_file(params, filename)
        self.job_id = test_job.id
        self.filepath, self.filename = general.get_filepath_filename(self.job_id, logger)
        self.md5 = test_job.md5

    def test_docinfo(self):
        report = doc_info.run("Doc_Info", self.job_id, self.filepath, self.filename, self.md5, {})
        self.assertEqual(report.get('success', False), True)


class FileAnalyzersRtfTests(TestCase):

    def setUp(self):
        params = {
            "source": "test",
            "is_sample": True,
            "file_mimetype": "text/rtf",
            "force_privacy": False,
            "analyzers_requested": ["test"]
        }
        filename = "document.rtf"
        test_job = _generate_test_job_with_file(params, filename)
        self.job_id = test_job.id
        self.filepath, self.filename = general.get_filepath_filename(self.job_id, logger)
        self.md5 = test_job.md5

    def test_rtfinfo(self):
        report = rtf_info.run("Rtf_Info", self.job_id, self.filepath, self.filename, self.md5, {})
        self.assertEqual(report.get('success', False), True)


class FileAnalyzersPDFTests(TestCase):

    def setUp(self):
        params = {
            "source": "test",
            "is_sample": True,
            "file_mimetype": "application/pdf",
            "force_privacy": False,
            "analyzers_requested": ["test"]
        }
        filename = "document.pdf"
        test_job = _generate_test_job_with_file(params, filename)
        self.job_id = test_job.id
        self.filepath, self.filename = general.get_filepath_filename(self.job_id, logger)
        self.md5 = test_job.md5

    def test_pdfinfo(self):
        report = pdf_info.run("PDF_Info", self.job_id, self.filepath, self.filename, self.md5, {})
        self.assertEqual(report.get('success', False), True)


def _generate_test_job_with_file(params, filename):
    test_file = "{}/test_files/{}".format(settings.PROJECT_LOCATION, filename)
    with open(test_file, "rb") as f:
        django_file = File(f)
        params['file'] = django_file
        params['md5'] = hashlib.md5(django_file.file.read()).hexdigest()
        test_job = Job(**params)
        test_job.save()
    return test_job
