# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import hashlib
from django.test import TestCase

from api_app.models import Job
from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer
from api_app.analyzers_manager import controller as analyzers_controller

from .utils import if_mock, patch, mocked_requests

# for observable analyzers, if can customize the behavior based on:
# DISABLE_LOGGING_TEST to True -> logging disabled
# MOCK_CONNECTIONS to True -> connections to external analyzers are faked


@if_mock(
    [
        patch("requests.get", side_effect=mocked_requests),
        patch("requests.post", side_effect=mocked_requests),
    ]
)
class _ObservableAnalyzersScriptsTestCase(TestCase):

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
        raise cls.skipTest("abstract test case")

    def setUp(self):
        # analyzer config
        self.analyzer_config: dict = AnalyzerConfigSerializer.read_and_verify_config()
        # define runtime configs
        self.runtime_configuration = {
            "HoneyDB": {"honeydb_analysis": "ip_info"},
            "Thug_URL_Info": {"test": True},
            "Triage_Search": {"analysis_type": "submit"},
            "FILE_INFO": {"rank_strings": False},
        }
        # save job
        params = self.get_params()
        params["md5"] = hashlib.md5(
            params["observable_name"].encode("utf-8")
        ).hexdigest()
        self.test_job = Job(**params)
        self.test_job.save()
        # filter analyzers list
        self.filtered_analyzers_dictlist: list = [
            config
            for config in self.analyzer_config.values()
            if params["observable_classification"] in config["observable_supported"]
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
            print(analyzer_instance.analyzer_name, analyzer_instance.report.report)
            # asserts
            self.assertEqual(
                analyzer_instance._job.pk,
                self.test_job.pk,
            )
            self.assertEqual(
                analyzer_instance.report.status,
                analyzer_instance.report.Statuses.SUCCESS.name,
            )
