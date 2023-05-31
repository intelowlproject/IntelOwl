# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import hashlib
import os
from typing import Tuple

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile

from api_app import models

from .. import CustomAPITestCase

User = get_user_model()


class ApiViewTests(CustomAPITestCase):
    def setUp(self):
        super().setUp()
        self.uploaded_file, self.file_md5 = self.__get_test_file("file.exe")
        self.uploaded_file2, self.file_md52 = self.__get_test_file("file.exe")
        self.analyze_file_data = {
            "file": self.uploaded_file,
            "analyzers_requested": [
                "File_Info",
                "PE_Info",
            ],
            "connectors_requested": [],
            "file_name": "file.exe",
            "file_mimetype": "application/x-dosexec",
        }

        self.analyze_multiple_files_data = {
            "files": [self.uploaded_file, self.uploaded_file2],
            "analyzers_requested": [
                "File_Info",
                "PE_Info",
            ],
            "connectors_requested": [],
            "file_mimetypes": [
                "application/x-dosexec",
                "application/x-dosexec",
            ],
        }

        self.analyze_multiple_files_filenames = [
            "file.exe",
            "file.exe",
        ]

        self.observable_name = os.environ.get("TEST_IP", "8.8.8.8")
        self.observable_md5 = hashlib.md5(
            self.observable_name.encode("utf-8")
        ).hexdigest()
        self.analyze_observable_ip_data = {
            "observable_name": self.observable_name,
            "analyzers_requested": ["AbuseIPDB", "Stratosphere_Blacklist"],
            "connectors_requested": [],
            "observable_classification": "ip",
        }
        self.mixed_observable_data = {
            "observables": [
                ["ip", "8.8.8.8"],
                ["domain", "example.com"],
                ["ip", "8.8.2.2"],
            ],
            "analyzers_requested": ["Classic_DNS", "WhoIs_RipeDB_Search"],
            "connectors_requested": [],
            "tlp": "CLEAR",
            "runtime_configuration": {},
            "tags_labels": [],
        }

    @staticmethod
    def __get_test_file(fname: str) -> Tuple[SimpleUploadedFile, str]:
        floc = f"{settings.PROJECT_LOCATION}/test_files/{fname}"
        with open(floc, "rb") as f:
            binary = f.read()
        uploaded_file = SimpleUploadedFile(
            fname, binary, content_type="multipart/form-data"
        )
        md5 = hashlib.md5(binary).hexdigest()
        return uploaded_file, md5

    def test_ask_analysis_availability(self):
        md5 = os.environ.get("TEST_MD5", "446c5fbb11b9ce058450555c1c27153c")
        analyzers_needed = ["Classic_DNS", "CIRCLPassiveDNS"]
        data = {"md5": md5, "analyzers": analyzers_needed, "minutes_ago": 1}
        response = self.client.post(
            "/api/ask_analysis_availability", data, format="json"
        )
        self.assertEqual(response.status_code, 200)

    def test_ask_analysis_availability__run_all_analyzers(self):
        md5 = os.environ.get("TEST_MD5", "446c5fbb11b9ce058450555c1c27153c")
        data = {"md5": md5, "analyzers": []}
        response = self.client.post(
            "/api/ask_analysis_availability", data, format="json"
        )
        self.assertEqual(response.status_code, 200)

    def test_analyze_file__pcap(self):
        # with noone, only the PCAP analyzers should be executed
        analyzers_requested = []
        file_name = "example.pcap"
        uploaded_file, md5 = self.__get_test_file(file_name)
        file_mimetype = "application/vnd.tcpdump.pcap"
        data = {
            "file": uploaded_file,
            "analyzers_requested": analyzers_requested,
            "file_name": file_name,
            "file_mimetype": file_mimetype,
        }

        response = self.client.post("/api/analyze_file", data, format="multipart")
        content = response.json()
        msg = (response.status_code, content)
        self.assertEqual(response.status_code, 200, msg=msg)

        job_id = int(content["job_id"])
        job = models.Job.objects.get(pk=job_id)
        self.assertEqual(file_name, job.file_name)
        self.assertEqual(file_mimetype, job.file_mimetype)
        self.assertEqual(md5, job.md5)
        # there is only Suricata right now
        self.assertCountEqual(
            ["Suricata"],
            list(job.analyzers_to_execute.all().values_list("name", flat=True)),
        )

    def test_analyze_file__corrupted_sample(self):
        analyzers_requested = [
            "File_Info",
        ]
        file_name = "non_valid_pe.exe"
        uploaded_file, md5 = self.__get_test_file(file_name)
        file_mimetype = "application/x-dosexec"
        data = {
            "file": uploaded_file,
            "analyzers_requested": analyzers_requested,
            "file_name": file_name,
            "file_mimetype": file_mimetype,
        }

        response = self.client.post("/api/analyze_file", data, format="multipart")
        content = response.json()
        msg = (response.status_code, content)
        self.assertEqual(response.status_code, 200, msg=msg)

        job_id = int(content["job_id"])
        job = models.Job.objects.get(pk=job_id)
        self.assertEqual(file_name, job.file_name)
        self.assertEqual(file_mimetype, job.file_mimetype)
        self.assertEqual(md5, job.md5)
        self.assertCountEqual(
            analyzers_requested,
            list(job.analyzers_requested.all().values_list("name", flat=True)),
        )

    def test_analyze_file__exe(self):
        data = self.analyze_file_data.copy()
        response = self.client.post("/api/analyze_file", data, format="multipart")
        content = response.json()
        msg = (response.status_code, content)
        self.assertEqual(response.status_code, 200, msg=msg)
        job_id = int(content["job_id"])
        job = models.Job.objects.get(pk=job_id)
        self.assertEqual(response.status_code, 200, msg=msg)
        self.assertEqual(data["file_name"], job.file_name, msg=msg)
        self.assertEqual(data["file_mimetype"], job.file_mimetype, msg=msg)
        self.assertCountEqual(
            data["analyzers_requested"],
            list(job.analyzers_requested.all().values_list("name", flat=True)),
            msg=msg,
        )
        self.assertEqual(self.file_md5, job.md5, msg=msg)

    def test_analyze_file__guess_optional(self):
        data = self.analyze_file_data.copy()
        file_mimetype = data.pop("file_mimetype")  # let server guess it

        response = self.client.post("/api/analyze_file", data, format="multipart")
        content = response.json()
        msg = (response.status_code, content)
        self.assertEqual(response.status_code, 200, msg=msg)

        job_id = int(content["job_id"])
        job = models.Job.objects.get(pk=job_id)
        self.assertEqual(data["file_name"], job.file_name, msg=msg)
        self.assertCountEqual(
            data["analyzers_requested"],
            list(job.analyzers_requested.all().values_list("name", flat=True)),
            msg=msg,
        )
        self.assertEqual(file_mimetype, job.file_mimetype, msg=msg)
        self.assertEqual(self.file_md5, job.md5, msg=msg)

    def test_analyze_observable__domain(self):
        analyzers_requested = [
            "Classic_DNS",
        ]
        observable_name = os.environ.get("TEST_DOMAIN", "google.com")
        md5 = hashlib.md5(observable_name.encode("utf-8")).hexdigest()
        observable_classification = "domain"
        data = {
            "observable_name": observable_name,
            "analyzers_requested": analyzers_requested,
            "connectors_requested": [],
            "observable_classification": observable_classification,
            "tags_labels": ["test1", "test2"],
        }

        response = self.client.post("/api/analyze_observable", data, format="json")
        content = response.json()
        msg = (response.status_code, content)
        self.assertEqual(response.status_code, 200, msg=msg)

        job_id = int(content["job_id"])
        job = models.Job.objects.get(pk=job_id)
        self.assertEqual(observable_name, job.observable_name)
        self.assertEqual(observable_classification, job.observable_classification)
        self.assertEqual(md5, job.md5)
        self.assertCountEqual(
            analyzers_requested,
            list(job.analyzers_requested.all().values_list("name", flat=True)),
        )
        self.assertCountEqual(
            data["tags_labels"], list(job.tags.values_list("label", flat=True))
        )

    def test_analyze_observable__ip(self):
        data = self.analyze_observable_ip_data.copy()

        response = self.client.post("/api/analyze_observable", data, format="json")
        content = response.json()
        msg = (response.status_code, content)
        self.assertEqual(response.status_code, 200, msg=msg)

        job_id = int(content["job_id"])
        job = models.Job.objects.get(pk=job_id)
        self.assertEqual(data["observable_name"], job.observable_name, msg=msg)
        self.assertCountEqual(
            data["analyzers_requested"],
            list(job.analyzers_requested.all().values_list("name", flat=True)),
            msg=msg,
        )
        self.assertEqual(
            data["observable_classification"], job.observable_classification, msg=msg
        )
        self.assertEqual(self.observable_md5, job.md5, msg=msg)

    def test_analyze_observable__guess_optional(self):
        data = self.analyze_observable_ip_data.copy()
        observable_classification = data.pop(
            "observable_classification"
        )  # let the server calc it

        response = self.client.post("/api/analyze_observable", data, format="json")
        content = response.json()
        msg = (response.status_code, content)
        self.assertEqual(response.status_code, 200, msg=msg)

        job_id = int(content["job_id"])
        job = models.Job.objects.get(pk=job_id)
        self.assertEqual(data["observable_name"], job.observable_name, msg=msg)
        self.assertCountEqual(
            data["analyzers_requested"],
            list(job.analyzers_requested.all().values_list("name", flat=True)),
            msg=msg,
        )
        self.assertEqual(
            observable_classification, job.observable_classification, msg=msg
        )
        self.assertEqual(self.observable_md5, job.md5, msg=msg)

    def test_analyze_multiple_observables(self):
        data = self.mixed_observable_data.copy()

        response = self.client.post(
            "/api/analyze_multiple_observables", data, format="json"
        )
        contents = response.json()
        msg = (response.status_code, contents)
        self.assertEqual(response.status_code, 200, msg=msg)

        content = contents["results"][0]

        job_id = int(content["job_id"])
        job = models.Job.objects.get(pk=job_id)
        self.assertEqual(data["observables"][0][1], job.observable_name, msg=msg)
        self.assertCountEqual(
            data["analyzers_requested"],
            list(job.analyzers_requested.all().values_list("name", flat=True)),
            msg=msg,
        )
        self.assertCountEqual(
            data["analyzers_requested"],
            list(job.analyzers_to_execute.all().values_list("name", flat=True)),
            msg=msg,
        )

        content = contents["results"][1]

        job_id = int(content["job_id"])
        job = models.Job.objects.get(pk=job_id)
        self.assertEqual(data["observables"][1][1], job.observable_name, msg=msg)
        self.assertCountEqual(
            [data["analyzers_requested"][0]],
            list(job.analyzers_to_execute.all().values_list("name", flat=True)),
            msg=msg,
        )

    def test_download_sample_200(self):
        self.assertEqual(models.Job.objects.count(), 0)
        filename = "file.exe"
        uploaded_file, md5 = self.__get_test_file(filename)
        job = models.Job.objects.create(
            **{
                "md5": md5,
                "is_sample": True,
                "file_name": filename,
                "file_mimetype": "application/x-dosexec",
                "file": uploaded_file,
            }
        )
        self.assertEqual(models.Job.objects.count(), 1)
        response = self.client.get(f"/api/jobs/{job.id}/download_sample")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get("Content-Disposition"),
            f'attachment; filename="{job.file_name}"',
        )

    def test_download_sample_404(self):
        # requesting for an ID that we know does not exist in DB
        response = self.client.get("/api/jobs/999/download_sample")
        self.assertEqual(response.status_code, 404)

    def test_download_sample_400(self):
        # requesting for job where is_sample=False
        job = models.Job.objects.create(is_sample=False)
        response = self.client.get(f"/api/jobs/{job.id}/download_sample")
        content = response.json()
        msg = (response, content)
        self.assertEqual(response.status_code, 400, msg=msg)
        self.assertDictContainsSubset(
            {"detail": "Requested job does not have a sample associated with it."},
            content["errors"],
            msg=msg,
        )

    def test_no_analyzers(self):
        data = self.mixed_observable_data.copy()
        data["analyzers_requested"] = data["analyzers_requested"][1:]
        response = self.client.post(
            "/api/analyze_multiple_observables", data, format="json"
        )
        contents = response.json()
        msg = (response.status_code, contents)
        self.assertEqual(response.status_code, 400, msg=msg)

    def test_incorrect_tlp(self):
        data = self.mixed_observable_data.copy()
        data["tlp"] = "incorrect"
        response = self.client.post(
            "/api/analyze_multiple_observables", data, format="json"
        )
        contents = response.json()
        msg = (response.status_code, contents)
        self.assertEqual(response.status_code, 400, msg=msg)
        error = contents["errors"]["detail"][0]
        self.assertEqual(error["tlp"][0], '"incorrect" is not a valid choice.', msg=msg)
        error = contents["errors"]["detail"][1]
        self.assertEqual(error["tlp"][0], '"incorrect" is not a valid choice.', msg=msg)

    def test_ask_multi_analysis_availability(self):
        md5 = os.environ.get("TEST_MD5", "446c5fbb11b9ce058450555c1c27153c")
        analyzers_needed = ["Classic_DNS", "CIRCLPassiveDNS"]
        data = [{"md5": md5, "analyzers": analyzers_needed, "minutes_ago": 1}]
        response = self.client.post(
            "/api/ask_multi_analysis_availability", data, format="json"
        )
        self.assertEqual(response.status_code, 200)

    def test_analyze_multiple_files__exe(self):
        data = self.analyze_multiple_files_data.copy()
        response = self.client.post(
            "/api/analyze_multiple_files", data, format="multipart"
        )
        contents = response.json()
        msg = (response.status_code, contents)
        self.assertEqual(response.status_code, 200, msg=msg)
        self.assertEqual(contents["count"], len(data["files"]), msg=msg)
        for index, content in enumerate(contents["results"]):
            job_id = int(content["job_id"])
            job = models.Job.objects.get(pk=job_id)
            self.assertEqual(response.status_code, 200, msg=msg)
            self.assertEqual(
                self.analyze_multiple_files_filenames[index], job.file_name, msg=msg
            )
            self.assertCountEqual(
                data["analyzers_requested"],
                list(job.analyzers_requested.all().values_list("name", flat=True)),
                msg=msg,
            )
            self.assertEqual(self.file_md5, job.md5, msg=msg)
            self.assertEqual(data["file_mimetypes"][index], job.file_mimetype, msg=msg)

    def test_analyze_multiple_files__guess_optional(self):
        data = self.analyze_multiple_files_data.copy()
        file_mimetypes = data.pop("file_mimetypes")
        response = self.client.post(
            "/api/analyze_multiple_files", data, format="multipart"
        )
        contents = response.json()
        msg = (response.status_code, contents)
        self.assertEqual(response.status_code, 200, msg=msg)
        self.assertEqual(contents["count"], len(data["files"]), msg=msg)
        for index, content in enumerate(contents["results"]):
            job_id = int(content["job_id"])
            job = models.Job.objects.get(pk=job_id)
            self.assertEqual(response.status_code, 200, msg=msg)
            self.assertEqual(
                self.analyze_multiple_files_filenames[index], job.file_name, msg=msg
            )
            self.assertCountEqual(
                data["analyzers_requested"],
                list(job.analyzers_requested.all().values_list("name", flat=True)),
                msg=msg,
            )
            self.assertEqual(self.file_md5, job.md5, msg=msg)
            self.assertEqual(file_mimetypes[index], job.file_mimetype, msg=msg)

    def test_tlp_clear_and_white(self):
        data = self.analyze_observable_ip_data.copy()  # tlp = "CLEAR" by default
        response = self.client.post("/api/analyze_observable", data, format="json")
        contents = response.json()
        msg = (response.status_code, contents)
        self.assertEqual(response.status_code, 200, msg=msg)
        job_id = int(contents["job_id"])
        job = models.Job.objects.get(pk=job_id)
        self.assertEqual(job.tlp, "CLEAR", msg=msg)

        data["tlp"] = "CLEAR"
        response = self.client.post("/api/analyze_observable", data, format="json")
        contents = response.json()
        msg = (response.status_code, contents)
        self.assertEqual(response.status_code, 200, msg=msg)
        job_id = int(contents["job_id"])
        job = models.Job.objects.get(pk=job_id)
        self.assertEqual(job.tlp, "CLEAR", msg=msg)
