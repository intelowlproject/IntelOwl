# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import hashlib
import logging

from django.core.files import File
from django.test import TestCase
from unittest.mock import patch, MagicMock

from api_app.analyzers_manager.file_analyzers import mwdb_scan
from api_app.models import Job

from intel_owl import settings


def mocked_mwdb_response(*args, **kwargs):
    attrs = {"data": {"id": "id_test"}, "metakeys": {"karton": "test_analysis"}}
    fileInfo = MagicMock()
    fileInfo.configure_mock(**attrs)
    QueryResponse = MagicMock()
    attrs = {"query_file.return_value": fileInfo}
    QueryResponse.configure_mock(**attrs)
    Response = MagicMock(return_value=QueryResponse)
    return Response.return_value


# disable logging library for Continuous Integration
if settings.DISABLE_LOGGING_TEST:
    logging.disable(logging.CRITICAL)


def get_filepath_filename(job_object: Job):
    filename = job_object.file_name
    file_path = job_object.file.path
    return file_path, filename


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
        self.filepath, self.filename = get_filepath_filename(self.job_id)
        self.md5 = test_job.md5

    @patch("mwdblib.MWDB", side_effect=mocked_mwdb_response)
    @patch.object(mwdb_scan.MWDB_Scan, "file_analysis", return_value=True)
    def test_mwdb_scan_uploadfile(self, mock_get=None, mock_post=None):
        additional_params = {
            "api_key_name": "test_api",
            "upload_file": True,
            "max_tries": 20,
        }
        report = mwdb_scan.MWDB_Scan(
            "MWDB_Scan",
            self.job_id,
            self.filepath,
            self.filename,
            self.md5,
            additional_params,
        ).start()
        self.assertEqual(report.status, report.Statuses.SUCCESS.name)


def _generate_test_job_with_file(params, filename):
    test_file = f"{settings.PROJECT_LOCATION}/test_files/{filename}"
    with open(test_file, "rb") as f:
        django_file = File(f)
        params["file"] = django_file
        params["md5"] = hashlib.md5(django_file.file.read()).hexdigest()
        test_job = Job(**params)
        test_job.save()
    return test_job
