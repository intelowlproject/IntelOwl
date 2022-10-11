# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from django.test import TestCase

from api_app.analyzers_manager.dataclasses import AnalyzerConfig
from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer
from api_app.serializers import ObservableAnalysisSerializer
from tests import User


class AnalyzerConfigTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

    def setUp(self):
        self.serializer_class = ObservableAnalysisSerializer
        self.superuser = User.objects.create_superuser(
            username="test", email="test@intelowl.com", password="test"
        )

    def test_config_not_empty(self):
        config = AnalyzerConfigSerializer.read_and_verify_config()
        self.assertNotEqual(config, {})

    def test_stack_analyzers(self):
        analyzers_used = ["Classic_DNS"]
        data = {
            "observables": [
                ["url", "google.com"],
            ],
            "analyzers_requested": analyzers_used,
            "connectors_requested": [],
            "tlp": "WHITE",
            "runtime_configuration": {},
            "tags_labels": [],
        }

        serializer = self.serializer_class(data=data, many=True)
        serializer.is_valid(raise_exception=True)

        serialized_data = serializer.validated_data
        [data.pop("runtime_configuration", {}) for data in serialized_data]

        config = AnalyzerConfigSerializer.read_and_verify_config()
        enabled_analyzers = [
            i
            for i in config
            if config[i]["verification"]["configured"] and not config[i]["disabled"]
        ]

        test_jobs = serializer.save(
            user=self.superuser,
        )

        for job in test_jobs:
            cleaned_result = AnalyzerConfig.stack_analyzers(
                job_id=job.pk,
                analyzers_to_execute=job.analyzers_to_execute,
                runtime_configuration={},
                parent_playbook="",
            )

            signatures = cleaned_result[0]
            analyzers_ran = cleaned_result[1]

            self.assertEqual(analyzers_used, analyzers_ran)
            # ^ Adding this here because "CLASSIC_DNS"
            # should be by default activated and working.

            self.assertNotEqual([], signatures)
            self.assertTrue(set(enabled_analyzers).issuperset(set(analyzers_ran)))

    def test_stack_analyzers_all(self):
        analyzers_used = []
        data = {
            "observables": [
                ["url", "google.com"],
            ],
            "analyzers_requested": analyzers_used,
            "connectors_requested": [],
            "tlp": "WHITE",
            "runtime_configuration": {},
            "tags_labels": [],
        }

        serializer = self.serializer_class(data=data, many=True)
        serializer.is_valid(raise_exception=True)

        serialized_data = serializer.validated_data
        [data.pop("runtime_configuration", {}) for data in serialized_data]

        config = AnalyzerConfigSerializer.read_and_verify_config()
        enabled_analyzers = [
            i
            for i in config
            if config[i]["verification"]["configured"] and not config[i]["disabled"]
        ]

        test_jobs = serializer.save(
            user=self.superuser,
        )

        for job in test_jobs:
            cleaned_result = AnalyzerConfig.stack_analyzers(
                analyzers_to_execute=job.analyzers_to_execute,
                runtime_configuration={},
                parent_playbook=None,
                job_id=job.pk,
            )

            analyzers_ran = cleaned_result[1]
            signatures = cleaned_result[0]

            self.assertNotEqual(analyzers_ran, analyzers_used)
            # ^ [] != ALL the analyzers.

            self.assertNotEqual([], signatures)
            self.assertTrue(set(enabled_analyzers).issuperset(set(analyzers_ran)))
