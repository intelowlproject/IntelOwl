# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.dataclasses import AnalyzerConfig
from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer
from api_app.serializers import ObservableAnalysisSerializer

from .. import CustomTestCase


class AnalyzerConfigTestCase(CustomTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

    def setUp(self):
        self.serializer_class = ObservableAnalysisSerializer
        super().setUp()

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

        config = AnalyzerConfigSerializer.read_and_verify_config()
        enabled_analyzers = [
            i
            for i in config
            if config[i]["verification"]["configured"] and not config[i]["disabled"]
        ]

        test_jobs = serializer.save(
            user=self.superuser,
        )

        from api_app.models import PluginConfig

        configs = PluginConfig.objects.filter(
            type=PluginConfig.PluginType.ANALYZER,
            config_type=PluginConfig.ConfigType.SECRET,
            owner=self.superuser,
        )
        print("printing found config for superuser for analyzers")
        for config in configs:
            print(f"attribute: {config.attribute}, value: {config.value}")

        for job in test_jobs:
            cleaned_result = AnalyzerConfig.stack(
                job_id=job.pk,
                plugins_to_execute=job.analyzers_to_execute,
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

        config = AnalyzerConfigSerializer.read_and_verify_config()
        enabled_analyzers = [
            i
            for i in config
            if config[i]["verification"]["configured"] and not config[i]["disabled"]
        ]

        test_jobs = serializer.save(
            user=self.superuser,
        )

        from api_app.models import PluginConfig

        configs = PluginConfig.objects.filter(
            type=PluginConfig.PluginType.ANALYZER,
            config_type=PluginConfig.ConfigType.SECRET,
            owner=self.superuser,
        )
        print("printing found config for superuser for analyzers")
        for config in configs:
            print(f"attribute: {config.attribute}, value: {config.value}")

        for job in test_jobs:
            cleaned_result = AnalyzerConfig.stack(
                plugins_to_execute=job.analyzers_to_execute,
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
