import hashlib
import logging
import os

from django.core.files import File
from django.test import TestCase

from api_app.script_analyzers import general
from api_app.script_analyzers.file_analyzers import file_info, pe_info, doc_info, pdf_info, vt2_scan, intezer_scan, \
    cuckoo_scan, yara_scan, vt3_scan, strings_info, rtf_info
from api_app.script_analyzers.observable_analyzers import abuseipdb, fortiguard, maxmind, greynoise, googlesf, otx, \
    talos, tor, circl_pssl, circl_pdns, robtex_ip, robtex_fdns, robtex_rdns, vt2_get, ha_get, vt3_get, misp

from api_app import crons
from api_app.models import Job
from api_app.script_analyzers.file_analyzers import signature_info
from api_app.utilities import get_analyzer_config

from intel_owl import settings, secrets

from pyintelowl.pyintelowl import IntelOwl

logger = logging.getLogger(__name__)


class ApiTests(TestCase):

    def setUp(self):
        self.client = IntelOwl(secrets.get_secret("TEST_TOKEN"), False,
                               "http://nginx", True)

    def test_ask_analysis_availability(self):
        md5 = os.environ.get("TEST_MD5", "")
        analyzers_needed = ["Fortiguard", "CIRCLPassiveDNS"]
        api_request_result = self.client.ask_analysis_availability(md5, analyzers_needed)
        answer = api_request_result.get('answer', {})
        print(answer)
        errors = api_request_result.get('errors', [])
        self.assertFalse(errors)

    def test_send_corrupted_sample_pe(self):
        filename = "non_valid_pe.exe"
        test_file = "{}/test_files/{}".format(settings.PROJECT_LOCATION, filename)
        with open(test_file, "rb") as f:
            binary = f.read()
        md5 = hashlib.md5(binary).hexdigest()
        analyzers_requested = ["File_Info", "PE_Info", "Strings_Info_Classic", "Signature_Info"]
        api_request_result = self.client.send_file_analysis_request(md5, analyzers_requested, filename,
                                                                    binary, False)
        answer = api_request_result.get('answer', {})
        print(answer)
        errors = api_request_result.get('errors', [])
        self.assertFalse(errors)

    def test_send_analysis_request_sample(self):
        filename = "file.exe"
        test_file = "{}/test_files/{}".format(settings.PROJECT_LOCATION, filename)
        with open(test_file, "rb") as f:
            binary = f.read()
        md5 = hashlib.md5(binary).hexdigest()
        analyzers_requested = ["Yara_Scan", "HybridAnalysis_Get_File", "Cuckoo_ScanClassic", "Intezer_Scan",
                               "VirusTotal_v3_Get_File", "VirusTotal_v3_Scan_File", "File_Info", "PE_Info",
                               "Doc_Info", "PDF_Info", "Strings_Info_Classic", "Strings_Info_ML"]
        api_request_result = self.client.send_file_analysis_request(md5, analyzers_requested, filename,
                                                                    binary, False)
        answer = api_request_result.get('answer', {})
        print(answer)
        errors = api_request_result.get('errors', [])
        self.assertFalse(errors)

    def test_send_analysis_request_domain(self):
        analyzers_requested = ["Fortiguard", "CIRCLPassiveDNS", "GoogleSafebrowsing", "Robtex_Forward_PDNS_Query",
                               "OTXQuery", "VirusTotal_v3_Get_Observable", "HybridAnalysis_Get_Observable"]
        observable_name = os.environ.get("TEST_DOMAIN", "")
        md5 = hashlib.md5(observable_name.encode('utf-8')).hexdigest()
        api_request_result = self.client.send_observable_analysis_request(md5, analyzers_requested,
                                                                          observable_name, False)
        answer = api_request_result.get('answer', {})
        print(answer)
        errors = api_request_result.get('errors', [])
        self.assertFalse(errors)

    def test_send_analysis_request_ip(self):
        analyzers_requested = ["TorProject", "AbuseIPDB", "MaxMindGeoIP", "CIRCLPassiveSSL",
                               "GreyNoiseAlpha", "GoogleSafebrowsing", "Robtex_IP_Query",
                               "Robtex_Reverse_PDNS_Query", "TalosReputation", "OTXQuery",
                               "VirusTotal_Get_v2_Observable", "HybridAnalysis_Get_Observable"]
        observable_name = os.environ.get("TEST_IP", "")
        md5 = hashlib.md5(observable_name.encode('utf-8')).hexdigest()
        api_request_result = self.client.send_observable_analysis_request(md5, analyzers_requested,
                                                                          observable_name, False)
        answer = api_request_result.get('answer', {})
        print(answer)
        errors = api_request_result.get('errors', [])
        self.assertFalse(errors)

    def test_ask_analysis_result(self):
        # put your test job_id
        job_id = os.environ.get("TEST_JOB_ID", "")
        api_request_result = self.client.ask_analysis_result(job_id)
        answer = api_request_result.get('answer', {})
        print(answer)
        errors = api_request_result.get('errors', [])
        self.assertFalse(errors)


class CronTests(TestCase):

    def test_check_stuck_analysis(self):
        jobs_id_stuck = crons.check_stuck_analysis()
        print("jobs_id_stuck: {}".format(jobs_id_stuck))
        self.assertTrue(True)

    def test_remove_old_jobs(self):
        num_jobs_to_delete = crons.remove_old_jobs()
        print("old jobs deleted: {}".format(num_jobs_to_delete))
        self.assertTrue(True)

    def test_maxmind_updater(self):
        db_file_path = maxmind.updater()
        self.assertTrue(os.path.exists(db_file_path))

    def test_talos_updater(self):
        db_file_path = talos.updater()
        self.assertTrue(os.path.exists(db_file_path))

    def test_tor_updater(self):
        db_file_path = tor.updater()
        self.assertTrue(os.path.exists(db_file_path))

    def test_yara_updater(self):
        file_paths = yara_scan.yara_update_repos()
        for file_path in file_paths:
            self.assertTrue(os.path.exists(file_path))


class ConfigTests(TestCase):

    def test_config(self):
        config = get_analyzer_config()
        self.assertNotEqual(config, {})


class IPAnalyzersTests(TestCase):

    def setUp(self):
        params = {
            "source": "test",
            "is_sample": False,
            "observable_name": os.environ.get("TEST_IP", ""),
            "observable_classification": "ip",
            "force_privacy": False,
            "analyzers_requested": ["test"]
        }
        params["md5"] = hashlib.md5(params['observable_name'].encode('utf-8')).hexdigest()
        test_job = Job(**params)
        test_job.save()
        self.job_id = test_job.id
        self.observable_name = test_job.observable_name
        self.observable_classification = test_job.observable_classification

    def test_abuseipdb(self):
        report = abuseipdb.run("AbuseIPDB", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_maxmind(self):
        report = maxmind.run("MaxMindDB", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_greynoise(self):
        report = greynoise.run("Greynoise", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_gsf(self):
        report = googlesf.run("GoogleSafeBrowsing", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_otx(self):
        report = otx.run("OTX", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_talos(self):
        report = talos.run("TalosReputation", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_tor(self):
        report = tor.run("TorProject", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_circl_pssl(self):
        report = circl_pssl.run("CIRCL_PSSL", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_robtex_ip(self):
        report = robtex_ip.run("Robtex_IP", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_robtex_rdns(self):
        report = robtex_rdns.run("Robtex_RDNS", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_vt_get(self):
        report = vt2_get.run("VT_v2_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_ha_get(self):
        report = ha_get.run("HA_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_vt3_get(self):
        report = vt3_get.run("VT_v3_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_misp_first(self):
        report = misp.run("MISP_FIRST", self.job_id, self.observable_name, self.observable_classification,
                          {'api_key_name': "FIRST_MISP_API", "url_key_name": "FIRST_MISP_URL"})
        self.assertEqual(report.get('success', False), True)


class DomainAnalyzersTests(TestCase):

    def setUp(self):
        params = {
            "source": "test",
            "is_sample": False,
            "observable_name": os.environ.get("TEST_DOMAIN", ""),
            "observable_classification": "domain",
            "force_privacy": False,
            "analyzers_requested": ["test"]
        }
        params["md5"] = hashlib.md5(params['observable_name'].encode('utf-8')).hexdigest()
        test_job = Job(**params)
        test_job.save()
        self.job_id = test_job.id
        self.observable_name = test_job.observable_name
        self.observable_classification = test_job.observable_classification

    def test_fortiguard(self):
        report = fortiguard.run("Fortiguard", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_gsf(self):
        report = googlesf.run("GoogleSafeBrowsing", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_otx(self):
        report = otx.run("OTX", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_circl_pdns(self):
        report = circl_pdns.run("CIRCL_PDNS", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_robtex_fdns(self):
        report = robtex_fdns.run("Robtex_FDNS", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_vt_get(self):
        report = vt2_get.run("VT_v2_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_ha_get(self):
        report = ha_get.run("HA_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_vt3_get(self):
        report = vt3_get.run("VT_v3_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_misp_first(self):
        report = misp.run("MISP_FIRST", self.job_id, self.observable_name, self.observable_classification,
                          {'api_key_name': "FIRST_MISP_API", "url_key_name": "FIRST_MISP_URL"})
        self.assertEqual(report.get('success', False), True)


class URLAnalyzersTests(TestCase):

    def setUp(self):
        params = {
            "source": "test",
            "is_sample": False,
            "observable_name": os.environ.get("TEST_URL", ""),
            "observable_classification": "url",
            "force_privacy": False,
            "analyzers_requested": ["test"]
        }
        params["md5"] = hashlib.md5(params['observable_name'].encode('utf-8')).hexdigest()
        test_job = Job(**params)
        test_job.save()
        self.job_id = test_job.id
        self.observable_name = test_job.observable_name
        self.observable_classification = test_job.observable_classification

    def test_fortiguard(self):
        report = fortiguard.run("Fortiguard", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_gsf(self):
        report = googlesf.run("GoogleSafeBrowsing", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_otx(self):
        report = otx.run("OTX", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_circl_pdns(self):
        report = circl_pdns.run("CIRCL_PDNS", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_robtex_fdns(self):
        report = robtex_fdns.run("Robtex_FDNS", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_vt_get(self):
        report = vt2_get.run("VT_v2_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_vt3_get(self):
        report = vt3_get.run("VT_v3_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)


class HashAnalyzersTests(TestCase):

    def setUp(self):
        params = {
            "source": "test",
            "is_sample": False,
            "observable_name": os.environ.get("TEST_MD5", ""),
            "observable_classification": "hash",
            "force_privacy": False,
            "analyzers_requested": ["test"]
        }
        params["md5"] = hashlib.md5(params['observable_name'].encode('utf-8')).hexdigest()
        test_job = Job(**params)
        test_job.save()
        self.job_id = test_job.id
        self.observable_name = test_job.observable_name
        self.observable_classification = test_job.observable_classification

    def test_otx(self):
        report = otx.run("OTX", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_vt_get(self):
        report = vt2_get.run("VT_v2_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_ha_get(self):
        report = ha_get.run("HA_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_vt3_get(self):
        report = vt3_get.run("VT_v3_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_misp_first(self):
        report = misp.run("MISP_FIRST", self.job_id, self.observable_name, self.observable_classification,
                          {'api_key_name': "FIRST_MISP_API", "url_key_name": "FIRST_MISP_URL"})
        self.assertEqual(report.get('success', False), True)


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
        test_job = generate_test_job_with_file(params, filename)
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
        report = intezer_scan.run("Intezer_Scan", self.job_id, self.filepath, self.filename, self.md5, {})
        self.assertEqual(report.get('success', False), True)

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
        test_job = generate_test_job_with_file(params, filename)
        self.job_id = test_job.id
        self.filepath, self.filename = general.get_filepath_filename(self.job_id, logger)
        self.md5 = test_job.md5

    def test_fileinfo_dll(self):
        report = file_info.run("File_Info", self.job_id, self.filepath, self.filename, self.md5, {})
        self.assertEqual(report.get('success', False), True)

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
        filename = "documento.doc"
        test_job = generate_test_job_with_file(params, filename)
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
        filename = "documento.rtf"
        test_job = generate_test_job_with_file(params, filename)
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
        filename = "malware.pdf"
        test_job = generate_test_job_with_file(params, filename)
        self.job_id = test_job.id
        self.filepath, self.filename = general.get_filepath_filename(self.job_id, logger)
        self.md5 = test_job.md5

    def test_pdfinfo(self):
        report = pdf_info.run("PDF_Info", self.job_id, self.filepath, self.filename, self.md5, {})
        self.assertEqual(report.get('success', False), True)


def generate_test_job_with_file(params, filename):
    test_file = "{}/test_files/{}".format(settings.PROJECT_LOCATION, filename)
    with open(test_file, "rb") as f:
        django_file = File(f)
        params['file'] = django_file
        params['md5'] = hashlib.md5(django_file.file.read()).hexdigest()
        test_job = Job(**params)
        test_job.save()
    return test_job


