import hashlib
import logging
import os

from django.contrib.auth.models import User
from django.test import TestCase
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework.test import APIClient

from intel_owl import settings
from api_app import models

logger = logging.getLogger(__name__)
# disable logging library
if settings.DISABLE_LOGGING_TEST:
    logging.disable(logging.CRITICAL)


class ApiViewTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super(ApiViewTests, cls).setUpClass()
        cls.superuser = User.objects.create_superuser(
            username="test", email="test@intelowl.com", password="test"
        )

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

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


class JobViewsetTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super(JobViewsetTests, cls).setUpClass()
        cls.superuser = User.objects.create_superuser(
            username="test", email="test@intelowl.com", password="test"
        )

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)
        self.job, _ = models.Job.objects.get_or_create(
            **{
                "id": 1,
                "observable_name": os.environ.get("TEST_IP"),
                "md5": os.environ.get("TEST_MD5"),
                "observable_classification": "ip",
                "is_sample": False,
                "run_all_available_analyzers": True,
            }
        )

    def test_list_all_jobs(self):
        response = self.client.get("/api/jobs")
        self.assertEqual(response.status_code, 200)

    def test_get_job_by_id_200(self):
        response = self.client.get(f"/api/jobs/{self.job.id}")
        self.assertEqual(response.status_code, 200)

    def test_get_job_by_id_404(self):
        # requesting for an ID that we know does not exist in DB
        response = self.client.get("/api/jobs/999")
        self.assertEqual(response.status_code, 404)

    def test_delete_job_by_id_204(self):
        self.assertEqual(models.Job.objects.count(), 1)
        response = self.client.delete(f"/api/jobs/{self.job.id}")
        self.assertEqual(response.status_code, 204)
        self.assertEqual(models.Job.objects.count(), 0)

    def test_delete_job_by_id_404(self):
        self.assertEqual(models.Job.objects.count(), 1)
        # requesting for an ID that we know does not exist in DB
        response = self.client.delete("/api/jobs/999")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(models.Job.objects.count(), 1)

    def test_kill_job_by_id_200(self):
        job = models.Job.objects.create(status="running")
        self.assertEqual(job.status, "running")
        response = self.client.patch(f"/api/jobs/{job.id}/kill")
        self.assertEqual(response.status_code, 200)
        job.refresh_from_db()
        self.assertEqual(job.status, "killed")

    def test_kill_job_by_id_404(self):
        response = self.client.patch("/api/jobs/999/kill")
        self.assertEqual(response.status_code, 404)

    def test_kill_job_by_id_400(self):
        # create a new job whose status is not "running"
        job = models.Job.objects.create(status="reported_without_fails")
        self.assertEqual(job.status, "reported_without_fails")
        response = self.client.patch(f"/api/jobs/{job.id}/kill")
        self.assertDictEqual(response.json(), {"detail": "Job is not running"})
        self.assertEqual(response.status_code, 400)


class TagViewsetTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super(TagViewsetTests, cls).setUpClass()
        cls.superuser = User.objects.create_superuser(
            username="test", email="test@intelowl.com", password="test"
        )

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)
        self.tag, _ = models.Tag.objects.get_or_create(
            id=1, label="Test", color="#FF5733"
        )

    def test_create_new_tag(self):
        self.assertEqual(models.Tag.objects.count(), 1)
        data = {"label": "testLabel", "color": "#91EE28"}
        response = self.client.post("/api/tags", data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(models.Tag.objects.count(), 2)

    def test_list_all_tags(self):
        response = self.client.get("/api/tags")
        self.assertEqual(response.status_code, 200)

    def test_get_tag_by_id_200(self):
        response = self.client.get(f"/api/tags/{self.tag.id}")
        self.assertEqual(response.status_code, 200)

    def test_get_tag_by_id_404(self):
        # requesting for an ID that we know does not exist in DB
        response = self.client.get("/api/tags/999")
        self.assertEqual(response.status_code, 404)

    def test_update_tag_by_id_200(self):
        new_data = {"label": "newTestLabel", "color": "#765A54"}
        response = self.client.put(f"/api/tags/{self.tag.id}", new_data)
        self.assertDictContainsSubset(response.json, new_data)
        self.assertEqual(response.status_code, 200)

    def test_update_tag_by_id_404(self):
        new_data = {"label": "newTestLabel", "color": "#765A54"}
        # requesting for an ID that we know does not exist in DB
        response = self.client.put("/api/tags/999", new_data)
        self.assertEqual(response.status_code, 404)

    def test_delete_tag_by_id_404(self):
        self.assertEqual(models.Tag.objects.count(), 1)
        # requesting for an ID that we know does not exist in DB
        response = self.client.delete("/api/tags/999")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(models.Tag.objects.count(), 1)

    def test_delete_tag_by_id_204(self):
        self.assertEqual(models.Tag.objects.count(), 1)
        response = self.client.delete(f"/api/tags/{self.tag.id}")
        self.assertEqual(response.status_code, 204)
        self.assertEqual(models.Tag.objects.count(), 0)
