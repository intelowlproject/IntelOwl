# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import hashlib
import os
import time
from unittest import SkipTest

from django.conf import settings
from django.core.files import File
from django.test import TransactionTestCase

from api_app.analyzers_manager.dataclasses import AnalyzerConfig
from api_app.connectors_manager.dataclasses import ConnectorConfig
from api_app.core.models import AbstractReport
from api_app.models import Job
from intel_owl.tasks import start_analyzers


class _AbstractAnalyzersScriptTestCase(TransactionTestCase):

    # constants
    TIMEOUT_SECONDS: int = 60 * 5  # 5 minutes
    SLEEP_SECONDS: int = 5  # 5 seconds
    analyzer_configs = AnalyzerConfig.all()
    connector_configs = ConnectorConfig.all()

    # attrs
    test_job: Job
    analyzer_configs: dict
    runtime_configuration: dict
    analyzers_to_test: list

    @classmethod
    def get_params(cls):
        return {
            "source": "test",
            "analyzers_requested": [],
            "connectors_requested": [],
            "connectors_to_execute": list(cls.connector_configs.keys()),
        }

    @classmethod
    def setUpClass(cls):
        if cls in [
            _AbstractAnalyzersScriptTestCase,
            _ObservableAnalyzersScriptsTestCase,
            _FileAnalyzersScriptsTestCase,
        ]:
            raise SkipTest(f"{cls.__name__} is an abstract base class.")
        return super().setUpClass()

    def setUp(self):
        analyzers_to_test = os.environ.get("TEST_ANALYZERS", "").split(",")
        self.analyzers_to_test = (
            analyzers_to_test
            if len(analyzers_to_test) and len(analyzers_to_test[0])
            else []
        )
        return super().setUp()

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
        # using `apply` so it runs synchronously, will block until the task returns
        start_analyzers(
            self.test_job.pk,
            self.test_job.analyzers_to_execute,
            self.runtime_configuration,
        )

        for i in range(0, int(self.TIMEOUT_SECONDS / self.SLEEP_SECONDS)):
            time.sleep(self.SLEEP_SECONDS)
            # reload test_job object
            self.test_job.refresh_from_db()
            status = self.test_job.status
            analyzers_stats = self.test_job.get_analyzer_reports_stats()
            connectors_stats = self.test_job.get_connector_reports_stats()
            running_or_pending_analyzers = list(
                self.test_job.analyzer_reports.filter(
                    status__in=[
                        AbstractReport.Status.PENDING,
                        AbstractReport.Status.RUNNING,
                    ]
                ).values_list("name", flat=True)
            )
            running_or_pending_connectors = list(
                self.test_job.connector_reports.filter(
                    status__in=[
                        AbstractReport.Status.PENDING,
                        AbstractReport.Status.RUNNING,
                    ]
                ).values_list("name", flat=True)
            )
            print(
                f"[REPORT] (poll #{i})",
                f"\n>>> Job:{self.test_job.pk}, status:'{status}'",
                f"\n>>> analyzer_reports:{analyzers_stats}",
                f"\n>>> connector_reports:{connectors_stats} ",
                f"\n>>> Running/Pending analyzers: {running_or_pending_analyzers}",
                f"\n>>> Running/Pending connectors: {running_or_pending_connectors}",
            )
            # fail immediately if any analyzer or connector failed
            if analyzers_stats["failed"] > 0 or connectors_stats["failed"] > 0:
                failed_analyzers = [
                    (r.analyzer_name, r.errors)
                    for r in self.test_job.analyzer_reports.filter(
                        status=AbstractReport.Status.FAILED
                    )
                ]
                failed_connectors = [
                    (r.connector_name, r.errors)
                    for r in self.test_job.connector_reports.filter(
                        status=AbstractReport.Status.FAILED
                    )
                ]
                print(
                    f"\n>>> Failed analyzers: {failed_analyzers}",
                    f"\n>>> Failed connectors: {failed_connectors}",
                )
                self.fail()
            # check analyzers status
            if status not in [Job.Status.PENDING, Job.Status.RUNNING]:
                self.assertEqual(
                    status,
                    Job.Status.REPORTED_WITHOUT_FAILS,
                    msg="`test_job` status must be success",
                )
                self.assertEqual(
                    len(self.test_job.analyzers_to_execute),
                    self.test_job.analyzer_reports.count(),
                    msg="all analyzer reports must be there",
                )
                self.assertEqual(
                    analyzers_stats["all"],
                    analyzers_stats["success"],
                    msg="all `analyzer_reports` status must be `SUCCESS`",
                )
                # check connectors status
                if connectors_stats["all"] > 0 and connectors_stats["running"] == 0:
                    self.assertEqual(
                        len(self.test_job.connectors_to_execute),
                        self.test_job.connector_reports.count(),
                        "all connector reports must be there",
                    )
                    self.assertEqual(
                        connectors_stats["all"],
                        connectors_stats["success"],
                        msg="all `connector_reports` status must be `SUCCESS`.",
                    )
                    print(
                        f"[END] -----{self.__class__.__name__}.test_start_analyzers----"
                    )
                    return True
        # the test should not reach here
        self.fail("test timed out")


class _ObservableAnalyzersScriptsTestCase(_AbstractAnalyzersScriptTestCase):

    # define runtime configs
    runtime_configuration = {
        "Triage_Search": {
            "analysis_type": "submit",
            "max_tries": 1,
            "endpoint": "public",
        },
        "VirusTotal_v3_Get_Observable": {
            "max_tries": 1,
            "poll_distance": 1,
        },
        "IntelX_Phonebook": {
            "timeout": -5,
        },
    }

    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "is_sample": False,
        }

    def setUp(self):
        super().setUp()
        # init job instance
        params = self.get_params()
        params["md5"] = hashlib.md5(
            params["observable_name"].encode("utf-8")
        ).hexdigest()
        self.test_job = Job(**params)
        # overwrite if not set in env var
        if len(self.analyzers_to_test):
            self.test_job.analyzers_to_execute = self.analyzers_to_test
        else:
            self.test_job.analyzers_to_execute = [
                config.name
                for config in self.analyzer_configs.values()
                if config.is_observable_type_supported(
                    params["observable_classification"]
                )
            ]
        # save job
        self.test_job.save()


class _FileAnalyzersScriptsTestCase(_AbstractAnalyzersScriptTestCase):

    # define runtime configs
    runtime_configuration = {
        "VirusTotal_v2_Scan_File": {"wait_for_scan_anyway": True, "max_tries": 1},
        "VirusTotal_v3_Scan_File": {"max_tries": 1, "poll_distance": 1},
        "VirusTotal_v3_Get_File": {"max_tries": 1, "poll_distance": 1},
        "VirusTotal_v3_Get_File_And_Scan": {
            "max_tries": 1,
            "poll_distance": 1,
            "force_active_scan": True,
            "force_active_scan_if_old": False,
        },
        "Cuckoo_Scan": {"max_poll_tries": 1, "max_post_tries": 1},
        "PEframe_Scan": {"max_tries": 1},
        "MWDB_Scan": {
            "upload_file": True,
            "max_tries": 1,
        },
        "Doc_Info_Experimental": {
            "additional_passwords_to_check": ["testpassword"],
            "experimental": True,
        },
    }

    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "is_sample": True,
        }

    def setUp(self):
        super().setUp()
        # get params
        params = self.get_params()
        # save job instance
        self.test_job = Job(**params)
        # overwrite if set in env var
        if len(self.analyzers_to_test):
            self.test_job.analyzers_to_execute = self.analyzers_to_test
        self._read_file_save_job(filename=params["file_name"])

    def _read_file_save_job(self, filename: str):
        test_file = f"{settings.PROJECT_LOCATION}/test_files/{filename}"
        with open(test_file, "rb") as f:
            self.test_job.file = File(f)
            self.test_job.md5 = hashlib.md5(f.read()).hexdigest()
            self.test_job.save()
