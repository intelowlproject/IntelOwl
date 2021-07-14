# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import hashlib
import time
from unittest.mock import patch

from django.test import TestCase
from django.core.files import File
from django.conf import settings

from api_app.models import Job
from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer
from api_app.analyzers_manager import controller as analyzers_controller
from api_app.analyzers_manager.models import AnalyzerReport

from ..mock_utils import if_mock, mocked_requests

# for observable analyzers, if can customize the behavior based on:
# DISABLE_LOGGING_TEST to True -> logging disabled
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

    def test_start_analyzers_all(self, *args, **kwargs):
        analyzers_controller.start_analyzers(
            job_id=self.test_job.pk,
            analyzers_to_execute=[c.name for c in self.filtered_analyzers_list],
            runtime_configuration=self.runtime_configuration,
        )

        while True:
            self.test_job.refresh_from_db()
            if self.test_job.status not in ["running", "pending"]:
                self.assertEquals(self.test_job.status, "reported_without_fails")
                num_all_reports = self.test_job.analyzer_reports.count()
                num_success_reports = self.test_job.analyzer_reports.filter(
                    status=AnalyzerReport.Statuses.SUCCESS.name
                ).count()
                self.assertEquals(
                    num_all_reports,
                    num_success_reports,
                    msg=f"report status must be {AnalyzerReport.Statuses.SUCCESS.name}",
                )
            time.sleep(5)


class _ObservableAnalyzersScriptsTestCase(_AbstractAnalyzersScriptTestCase):

    # define runtime configs
    runtime_configuration = {
        "Thug_URL_Info": {"test": True},
        "Triage_Search": {"analysis_type": "submit"},
    }

    def setUp(self):
        # analyzer config
        self.analyzer_configs = AnalyzerConfigSerializer.get_as_dataclasses()
        # save job
        params = self.get_params()
        params["md5"] = hashlib.md5(
            params["observable_name"].encode("utf-8")
        ).hexdigest()
        self.test_job = Job(**params)
        self.test_job.save()

        # filter analyzers list
        self.filtered_analyzers_list: list = [
            config
            for config in self.analyzer_configs.values()
            if config.is_observable_type_supported(params["observable_classification"])
        ]
        return super().setUp()

    def tearDown(self):
        self.test_job.delete()
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
            "api_key_name": "test_api",
            "upload_file": False,
            "max_tries": 20,
        },
        "Doc_Info_Experimental": {
            "additional_passwords_to_check": ["testpassword"],
            "experimental": True,
        },
        "Yara_Scan_McAfee": {
            "directories_with_rules": [
                "/opt/deploy/yara/mcafee_rules/APT",
                "/opt/deploy/yara/mcafee_rules/RAT",
                "/opt/deploy/yara/mcafee_rules/malware",
                "/opt/deploy/yara/mcafee_rules/miners",
                "/opt/deploy/yara/mcafee_rules/ransomware",
                "/opt/deploy/yara/mcafee_rules/stealer",
            ]
        },
        "Yara_Scan_Daily_Ioc": {
            "directories_with_rules": [
                "/opt/deploy/yara/daily_ioc_rules",
            ],
            "recursive": True,
        },
        "Yara_Scan_Stratosphere": {
            "directories_with_rules": [
                "/opt/deploy/yara/stratosphere_rules/malware",
                "/opt/deploy/yara/stratosphere_rules/protocols",
            ]
        },
        "Yara_Scan_Inquest": {
            "directories_with_rules": [
                "/opt/deploy/yara/inquest_rules",
                "/opt/deploy/yara/inquest_rules/labs.inquest.net",
            ]
        },
        "Yara_Scan_Intezer": {
            "directories_with_rules": [
                "/opt/deploy/yara/intezer_rules",
            ]
        },
        "Yara_Scan_ReversingLabs": {
            "directories_with_rules": ["/opt/deploy/yara/reversinglabs_rules/yara"],
            "recursive": True,
        },
        "Yara_Scan_Samir": {
            "directories_with_rules": [
                "/opt/deploy/yara/samir_rules",
            ]
        },
        "Yara_Scan_FireEye": {
            "directories_with_rules": [
                "/opt/deploy/yara/fireeye_rules/rules",
            ],
            "recursive": True,
        },
        "Yara_Scan_Florian": {
            "directories_with_rules": [
                "/opt/deploy/yara/signature-base/yara",
            ]
        },
        "Yara_Scan_Community": {
            "directories_with_rules": [
                "/opt/deploy/yara/rules",
            ]
        },
    }

    @staticmethod
    def _get_file(filename: str):
        test_file = f"{settings.PROJECT_LOCATION}/test_files/{filename}"
        with open(test_file, "rb") as f:
            django_file = File(f)
        return django_file

    def setUp(self):
        # analyzer config
        self.analyzer_configs = AnalyzerConfigSerializer.get_as_dataclasses()

        # save job
        params = self.get_params()
        params["file"] = self._get_file(params["file_name"])
        params["md5"] = hashlib.md5(params["file"].file.read()).hexdigest()
        self.test_job = Job(**params)
        self.test_job.save()

        # filter analyzers list
        self.filtered_analyzers_list: list = [
            config
            for config in self.analyzer_configs.values()
            if config.is_filetype_supported(params["file_mimetype"])
        ]
        return super().setUp()

    def tearDown(self):
        self.test_job.delete()
        return super().tearDown()

    def test_run_analyzer_all(self, *args, **kwargs):
        for config_dict in self.filtered_analyzers_dictlist:
            runtime_conf: dict = self.runtime_configuration.get(config_dict["name"], {})

            # merge config dict
            config_dict = {
                **config_dict,
                # merge config_dict["config"] with runtime_configuration
                "config": {
                    **config_dict["config"],
                    **runtime_conf,
                },
            }

            # run analyzer
            analyzer_instance = analyzers_controller.run_analyzer(
                self.test_job.pk,
                config_dict,
                job_id=self.test_job.pk,
                runtime_conf=runtime_conf,
            )
            # asserts
            self.assertEqual(
                analyzer_instance._job.pk,
                self.test_job.pk,
            )
            self.assertEqual(
                analyzer_instance.report.status,
                analyzer_instance.report.Statuses.SUCCESS.name,
            )
