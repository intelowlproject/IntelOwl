# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from django.test import TestCase

from api_app.connectors_manager.dataclasses import ConnectorConfig
from api_app.connectors_manager.serializers import ConnectorConfigSerializer
from api_app.serializers import ObservableAnalysisSerializer
from tests import User


class ConnectorConfigTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

    def setUp(self):
        self.serializer_class = ObservableAnalysisSerializer
        self.superuser = User.objects.create_superuser(
            username="test", email="test@intelowl.com", password="test"
        )

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

        serialized_data = serializer.validated_data
        [data.pop("runtime_configuration", {}) for data in serialized_data]

        test_jobs = serializer.save(
            user=self.superuser,
        )

        for job in test_jobs:
            cleaned_result = ConnectorConfig.stack_connectors(
                job_id=job.pk,
                analyzers_to_execute=job.analyzers_to_execute,
                runtime_configuration={},
                parent_playbook=None,
            )

            signatures = cleaned_result[0]
            connectors_ran = cleaned_result[1]

            self.assertNotEqual([], signatures)

            self.assertTrue(set(enabled_connectors).issuperset(set(connectors_ran)))
