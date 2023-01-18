# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.connectors_manager.dataclasses import ConnectorConfig
from api_app.connectors_manager.serializers import ConnectorConfigSerializer
from api_app.serializers import ObservableAnalysisSerializer

from .. import CustomTestCase


class ConnectorConfigTestCase(CustomTestCase):
    def setUp(self):
        self.serializer_class = ObservableAnalysisSerializer
        super().setUp()

    def test_config_not_empty(self):
        config = ConnectorConfigSerializer.read_and_verify_config()
        self.assertNotEqual(config, {})

    def test_stack_connectors(self):
        analyzers_used = ["Classic_DNS"]
        connectors_used = ["MISP", "OpenCTI", "YETI"]

        data = {
            "observables": [
                ["url", "google.com"],
            ],
            "analyzers_requested": analyzers_used,
            "connectors_requested": connectors_used,
            "tlp": "WHITE",
            "runtime_configuration": {},
            "tags_labels": [],
        }

        config = ConnectorConfigSerializer.read_and_verify_config()

        enabled_connectors = [
            (i)
            for i in config
            if not config[i]["disabled"] and config[i]["verification"]["configured"]
        ]

        serializer = self.serializer_class(data=data, many=True)
        serializer.is_valid(raise_exception=True)

        test_jobs = serializer.save(
            user=self.superuser,
        )

        from api_app.models import PluginConfig

        configs = PluginConfig.objects.filter(
            type=PluginConfig.PluginType.CONNECTOR,
            config_type=PluginConfig.ConfigType.SECRET,
            owner=self.superuser,
        )
        print("printing found config for superuser for connectors")
        for config in configs:
            print(f"attribute: {config.attribute}, value: {config.value}")

        configs = PluginConfig.objects.filter(
            type=PluginConfig.PluginType.ANALYZER,
            config_type=PluginConfig.ConfigType.SECRET,
            owner=self.superuser,
        )
        print("printing found config for superuser for analyzers")
        for config in configs:
            print(f"attribute: {config.attribute}, value: {config.value}")

        for job in test_jobs:
            cleaned_result = ConnectorConfig.stack(
                job_id=job.pk,
                plugins_to_execute=job.connectors_to_execute,
                runtime_configuration={},
            )

            connectors_ran = cleaned_result[1]

            self.assertTrue(set(enabled_connectors).issuperset(set(connectors_ran)))
