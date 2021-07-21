# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import hashlib
import time

from django.test import TransactionTestCase
from django.core.files import File
from django.conf import settings

from intel_owl.celery import app as celery_app
from api_app.models import Job
from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer

from ..mock_utils import if_mock_connections, patch, mocked_requests

# for observable analyzers, if can customize the behavior based on:
# MOCK_CONNECTIONS to True -> connections to external analyzers are faked


@if_mock_connections(
    patch("requests.get", side_effect=mocked_requests),
    patch("requests.post", side_effect=mocked_requests),
)
class _AbstractAnalyzersScriptTestCase(TransactionTestCase):

    # constants
    TIMEOUT_SECONDS: int = 120  # 2 minutes
    SLEEP_SECONDS: int = 5  # 5 seconds

    test_job: Job
    analyzer_configs: dict
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

    @classmethod
    def setUpTestData(cls):
        # analyzer config
        cls.analyzer_configs = AnalyzerConfigSerializer.get_as_dataclasses()
        return super().setUpTestData()

    def tearDown(self):
        self.test_job.delete()
        return super().tearDown()

    def test_start_analyzers(self, *args, **kwargs):
        print(f"\n[START] -----{self.__class__.__name__}.test_start_analyzers----")
        print(
            f"[REPORT] Job:{self.test_job.pk}, status:'{self.test_job.status}',",
            f"analyzers:{self.test_job.analyzers_to_execute}",
        )

        # execute analyzers
        celery_app.send_task(
            "start_analyzers",
            args=[
                self.test_job.pk,
                self.test_job.analyzers_to_execute,
                self.runtime_configuration,
            ],
        )

        for i in range(0, int(self.TIMEOUT_SECONDS / self.SLEEP_SECONDS)):
            time.sleep(self.SLEEP_SECONDS)
            self.test_job.refresh_from_db()
            status = self.test_job.status
            stats = self.test_job.get_analyzer_reports_stats()
            print(
                f"[REPORT] (poll #{i})",
                f"\n>>> Job:{self.test_job.pk}, status:'{status}', reports:{stats}",
            )
            if status not in ["running", "pending"]:
                self.assertEqual(status, "reported_without_fails")
                self.assertEqual(
                    stats["all"],
                    stats["success"],
                    msg="all reports status must be `SUCCESS`.",
                )
                print(f"[END] -----{self.__class__.__name__}.test_start_analyzers----")
                return True

        # the test should not reach here
        self.fail("test timed out")


class _ObservableAnalyzersScriptsTestCase(_AbstractAnalyzersScriptTestCase):

    # define runtime configs
    runtime_configuration = {
        "Thug_URL_Info": {"test": True},
        "Triage_Search": {
            "analysis_type": "submit",
            "max_tries": 1,
            "endpoint": "public",
        },
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
        self.test_job.analyzers_to_execute = ["Darksearch_Query"]
        # save job
        self.test_job.save()


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

    def _read_file_save_job(self, filename: str):
        test_file = f"{settings.PROJECT_LOCATION}/test_files/{filename}"
        with open(test_file, "rb") as f:
            self.test_job.file = File(f)
            self.test_job.md5 = hashlib.md5(f.read()).hexdigest()
            self.test_job.save()

    def setUp(self):
        super().setUp()
        # get params
        params = self.get_params()
        # filter analyzers list
        self.filtered_analyzers_list: list = [
            config
            for config in self.analyzer_configs.values()
            if config.is_type_file
            and config.is_filetype_supported(params["file_mimetype"])
        ]
        # save job instance
        self.test_job = Job(**params)
        self.test_job.analyzers_to_execute = [
            c.name for c in self.filtered_analyzers_list
        ]
        self._read_file_save_job(filename=params["file_name"])
