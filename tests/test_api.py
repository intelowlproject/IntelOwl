import hashlib
import logging
import os

from django.contrib.auth.models import User
from django.test import TestCase
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework.test import APIClient

from intel_owl import settings

logger = logging.getLogger(__name__)
# disable logging library
if settings.DISABLE_LOGGING_TEST:
    logging.disable(logging.CRITICAL)


class ApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="test", email="test@intelowl.com", password="test"
        )
        self.client.force_authenticate(user=self.user)

    def test_ask_analysis_availability(self):
        md5 = os.environ.get("TEST_MD5", "446c5fbb11b9ce058450555c1c27153c")
        analyzers_needed = ["Fortiguard", "CIRCLPassiveDNS"]
        params = {"md5": md5, "analyzers_needed": analyzers_needed}
        response = self.client.get(
            "/api/ask_analysis_availability", params, format="json"
        )
        self.assertEqual(response.status_code, 200)

    def test_ask_analysis_availability_run_all_analyzers(self):
        md5 = os.environ.get("TEST_MD5", "446c5fbb11b9ce058450555c1c27153c")
        params = {"md5": md5, "run_all_available_analyzers": True}
        response = self.client.get(
            "/api/ask_analysis_availability", params, format="json"
        )
        self.assertEqual(response.status_code, 200)

    def test_send_corrupted_sample_pe(self):
        filename = "non_valid_pe.exe"
        test_file = f"{settings.PROJECT_LOCATION}/test_files/{filename}"
        with open(test_file, "rb") as f:
            binary = f.read()
        md5 = hashlib.md5(binary).hexdigest()
        analyzers_requested = [
            "File_Info",
            "PE_Info",
            "Strings_Info_Classic",
            "Signature_Info",
        ]
        uploaded_file = SimpleUploadedFile(
            filename, binary, content_type="multipart/form-data"
        )
        data = {
            "md5": md5,
            "analyzers_requested": analyzers_requested,
            "is_sample": True,
            "file_name": filename,
            "file_mimetype": "application/x-dosexec",
            "file": uploaded_file,
            "test": True,
        }
        response = self.client.post(
            "/api/send_analysis_request", data, format="multipart"
        )
        self.assertEqual(response.status_code, 200)

    def test_send_analysis_request_sample(self):
        filename = "file.exe"
        test_file = f"{settings.PROJECT_LOCATION}/test_files/{filename}"
        with open(test_file, "rb") as f:
            binary = f.read()
        md5 = hashlib.md5(binary).hexdigest()
        analyzers_requested = [
            "Yara_Scan",
            "HybridAnalysis_Get_File",
            "Cuckoo_ScanClassic",
            "Intezer_Scan",
            "VirusTotal_v3_Get_File",
            "VirusTotal_v3_Scan_File",
            "File_Info",
            "PE_Info",
            "Doc_Info",
            "PDF_Info",
            "Strings_Info_Classic",
            "Strings_Info_ML",
            "MalwareBazaar_Get_File",
        ]
        uploaded_file = SimpleUploadedFile(
            filename, binary, content_type="multipart/form-data"
        )
        data = {
            "md5": md5,
            "analyzers_requested": analyzers_requested,
            "is_sample": True,
            "file_name": filename,
            "file_mimetype": "application/x-dosexec",
            "file": uploaded_file,
            "test": True,
        }
        response = self.client.post(
            "/api/send_analysis_request", data, format="multipart"
        )
        self.assertEqual(response.status_code, 200)

    def test_send_analysis_request_domain(self):
        analyzers_requested = [
            "Fortiguard",
            "CIRCLPassiveDNS",
            "Securitytrails_History_WHOIS",
            "Securitytrails_History_DNS",
            "Securitytrails_Tags",
            "Securitytrails_Subdomains",
            "Securitytrails_Details",
            "GoogleSafebrowsing",
            "Robtex_Forward_PDNS_Query",
            "OTXQuery",
            "VirusTotal_v3_Get_Observable",
            "HybridAnalysis_Get_Observable",
            "Threatminer_PDNS",
            "Threatminer_Reports_Tagging",
            "Threatminer_Subdomains",
            "ONYPHE",
            "URLhaus",
            "Pulsedive_Active_IOC",
        ]
        observable_name = os.environ.get("TEST_DOMAIN", "google.com")
        md5 = hashlib.md5(observable_name.encode("utf-8")).hexdigest()
        data = {
            "md5": md5,
            "analyzers_requested": analyzers_requested,
            "is_sample": False,
            "observable_name": observable_name,
            "observable_classification": "domain",
            "test": True,
        }
        response = self.client.post("/api/send_analysis_request", data)
        self.assertEqual(response.status_code, 200)

    def test_send_analysis_request_ip(self):
        analyzers_requested = [
            "TorProject",
            "AbuseIPDB",
            "Auth0",
            "Securitytrails_IP_Neighbours",
            "Shodan_Search",
            "Shodan_Honeyscore",
            "MaxMindGeoIP",
            "CIRCLPassiveSSL",
            "GreyNoiseAlpha",
            "GreyNoise",
            "GoogleSafebrowsing",
            "Robtex_IP_Query",
            "Robtex_Reverse_PDNS_Query",
            "TalosReputation",
            "OTXQuery",
            "VirusTotal_Get_v2_Observable",
            "HybridAnalysis_Get_Observable",
            "Hunter",
            "Threatminer_Reports_Tagging",
            "Threatminer_PDNS",
            "ONYPHE",
            "HoneyDB_Scan_Twitter",
            "HoneyDB_Get",
            "Pulsedive_Active_IOC",
        ]
        observable_name = os.environ.get("TEST_IP", "8.8.8.8")
        md5 = hashlib.md5(observable_name.encode("utf-8")).hexdigest()
        data = {
            "md5": md5,
            "analyzers_requested": analyzers_requested,
            "is_sample": False,
            "observable_name": observable_name,
            "observable_classification": "ip",
            "test": True,
        }
        response = self.client.post("/api/send_analysis_request", data)
        self.assertEqual(response.status_code, 200)

    def test_ask_analysis_result(self):
        # put your test job_id
        job_id = os.environ.get("TEST_JOB_ID", "1")
        data = {"job_id": job_id}
        response = self.client.get("/api/ask_analysis_result", data)
        self.assertEqual(response.status_code, 200)
