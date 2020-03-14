import hashlib
import logging
import os

from django.test import TestCase

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
        analyzers_requested = ["TorProject", "AbuseIPDB", "Shodan_Search", "Shodan_Honeyscore", "MaxMindGeoIP", "CIRCLPassiveSSL",
                               "GreyNoiseAlpha", "GoogleSafebrowsing", "Robtex_IP_Query",
                               "Robtex_Reverse_PDNS_Query", "TalosReputation", "OTXQuery",
                               "VirusTotal_Get_v2_Observable", "HybridAnalysis_Get_Observable", "Hunter",
                               "HoneyDB"]
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