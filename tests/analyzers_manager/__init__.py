# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import hashlib
import time
from unittest.mock import patch

from django.test import TestCase
from django.core.files import File
from django.conf import settings

from intel_owl.celery import app as celery_app
from api_app.models import Job
from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer
from api_app.analyzers_manager.models import AnalyzerReport

from ..mock_utils import if_mock, mocked_requests

# for observable analyzers, if can customize the behavior based on:
# MOCK_CONNECTIONS to True -> connections to external analyzers are faked


@if_mock(
    [
        patch("requests.get", side_effect=mocked_requests),
        patch("requests.post", side_effect=mocked_requests),
    ]
)
class _AbstractAnalyzersScriptTestCase(TestCase):

    test_job: Job
    analyzer_config: dict
    runtime_configuration: dict
    filtered_analyzers_dictlist: list

    @classmethod
    def get_params(cls):
        return {
            "source": "test",
            "is_sample": False,
            "force_privacy": False,
            "analyzers_requested": ["test"],
        }

    @classmethod
    def setUpClass(cls):
        if cls in [
            _AbstractAnalyzersScriptTestCase,
            _ObservableAnalyzersScriptsTestCase,
            _FileAnalyzersScriptsTestCase,
        ]:
            return cls.skipTest(f"{cls.__name__} is an abstract base class.")
        else:
            return super(_AbstractAnalyzersScriptTestCase, cls).setUpClass()

    def setUp(self):
        # cleanup
        # Job.objects.all().delete()
        # analyzer config
        self.analyzer_configs = AnalyzerConfigSerializer.get_as_dataclasses()
        return super().setUp()

    def test_start_analyzers_all(self, *args, **kwargs):
        print("\n[START] ---test_start_analyzers_all---")
        print(
            f"[REPORT] Job:{self.test_job.pk}, status:'{self.test_job.status}', analyzers:{self.test_job.analyzers_to_execute}"
        )

        # execute analyzers
        celery_app.send_task(
            "start_analyzers",
            args=[
                self.test_job.pk,
                self.test_job.analyzers_to_execute,
                self.runtime_configuration,
            ],
            queue="default",
        )

        for i in range(0, 1000):
            self.test_job.refresh_from_db()
            status = self.test_job.status
            stats = self.test_job.get_analyzer_reports_stats()
            print(
                f"[REPORT] (poll #{i})",
                f"\n>>> Job:{self.test_job.pk}, status:'{status}', reports:{stats}",
            )
            if status not in ["running", "pending"]:
                self.assertEquals(status, "reported_without_fails")
                self.assertEquals(
                    stats["all"],
                    stats["success"],
                    msg=f"report status must be SUCCESS",
                )
            time.sleep(5)

        print("[END] ---test_start_analyzers_all---")


class _ObservableAnalyzersScriptsTestCase(_AbstractAnalyzersScriptTestCase):

    # define runtime configs
    runtime_configuration = {
        "Thug_URL_Info": {"test": True},
        "Triage_Search": {"analysis_type": "submit"},
    }

    def setUp(self):
        super().setUp()
        # init job instance
        params = self.get_params()
        params["md5"] = hashlib.md5(
            params["observable_name"].encode("utf-8")
        ).hexdigest()
        self.test_job = Job(**params)
        # filter analyzers list
        self.filtered_analyzers_list: list = [
            config
            for config in self.analyzer_configs.values()
            if config.is_observable_type_supported(params["observable_classification"])
        ]
        self.test_job.analyzers_to_execute = [
            c.name for c in self.filtered_analyzers_list
        ]
        # save job
        self.test_job.save()

    def tearDown(self):
        # self.test_job.delete()
        return super().tearDown()


class _FileAnalyzersScriptsTestCase(_AbstractAnalyzersScriptTestCase):

    # define runtime configs
    runtime_configuration = {
        "Strings_Info_ML": {"rank_strings": False},
        "Qiling_Windows": {"os": "windows", "arch": "x86"},
        "VirusTotal_v2_Scan_File": {"wait_for_scan_anyway": True, "max_tries": 1},
        "VirusTotal_v3_Scan_File": {"max_tries": 1},
        "VirusTotal_v3_Get_File_And_Scan": {"max_tries": 1, "force_active_scan": True},
        "Intezer_Scan": {"max_tries": 1, "is_test": True},
        "Cuckoo_Scan": {"max_poll_tries": 1, "max_post_tries": 1},
        "PEframe_Scan": {"max_tries": 1},
        "MWDB_Scan": {
            "upload_file": False,
            "max_tries": 20,
        },
        "Doc_Info_Experimental": {
            "additional_passwords_to_check": ["testpassword"],
            "experimental": True,
        },
    }

    @staticmethod
    def _get_file(filename: str) -> File:
        test_file = f"{settings.PROJECT_LOCATION}/test_files/{filename}"
        with open(test_file, "rb") as f:
            django_file = File(f)
        return django_file

    def setUp(self):
        super().setUp()
        # init job instance
        params = self.get_params()
        params["file"] = self._get_file(params["file_name"])
        params["md5"] = hashlib.md5(params["file"].file.read()).hexdigest()
        self.test_job = Job(**params)
        # filter analyzers list
        self.filtered_analyzers_list: list = [
            config
            for config in self.analyzer_configs.values()
            if config.is_filetype_supported(params["file_mimetype"])
        ]
        self.test_job.analyzers_to_execute = [
            c.name for c in self.filtered_analyzers_list
        ]
        # save job
        self.test_job.save()

    def tearDown(self):
        self.test_job.delete()
        return super().tearDown()
