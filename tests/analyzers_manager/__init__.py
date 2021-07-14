# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import hashlib
import time
from unittest.mock import patch
from django.test import TestCase

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
        if cls is _ObservableAnalyzersScriptsTestCase:
            return cls.skipTest(f"{cls.__name__} is an abstract base class.")
        else:
            return super(_ObservableAnalyzersScriptsTestCase, cls).setUpClass()

    @classmethod
    def setUpTestData(cls):
        # analyzer config
        cls.analyzer_configs = AnalyzerConfigSerializer.get_as_dataclasses()
        # define runtime configs
        cls.runtime_configuration = {
            "Thug_URL_Info": {"test": True},
            "Triage_Search": {"analysis_type": "submit"},
        }
        return super().setUpTestData()

    def setUp(self):
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
                    msg=f"all reports status must be {AnalyzerReport.Statuses.SUCCESS.name}",
                )
            time.sleep(5)
