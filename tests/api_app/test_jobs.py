from django.test import TransactionTestCase

from api_app.models import Job, PluginConfig
from certego_saas.models import User


class JobTestCase(TransactionTestCase):
    PLAYBOOK = "FREE_TO_USE_ANALYZERS"

    def test_merge_configurations(self):
        user = User.objects.create_user(
            username="user",
            email="user@intelowl.com",
            password="test",
        )
        job = Job.objects.create(
            playbooks_to_execute=[self.PLAYBOOK],
            analyzers_to_execute=["AbuseIPDB"],
            user=user,
        )

        config = job._merge_runtime_configuration(
            {"AbuseIPDB": {"param1": 3}}, ["AbuseIPDB"], []
        )
        self.assertEqual(config, {"AbuseIPDB": {"param1": 3}})

        pc = PluginConfig.objects.create(
            type="1",
            config_type="1",
            plugin_name="AbuseIPDB",
            attribute="param1",
            value=122222,
            owner=user,
        )
        config = job._merge_runtime_configuration(
            {"AbuseIPDB": {"param1": 3}}, ["AbuseIPDB"], []
        )

        self.assertEqual(config, {"AbuseIPDB": {"param1": 122222}})

        pc.delete()
        job.delete()
        user.delete()

    def test_pipeline_configuration_no_playbook(self):
        job = Job.objects.create(analyzers_to_execute=["AbuseIPDB"])
        configs, analyzers, connectors = job._pipeline_configuration(
            {"AbuseIPDB": {"param1": 3}}
        )
        self.assertEqual(configs, [{"AbuseIPDB": {"param1": 3}}])
        self.assertEqual(analyzers, [["AbuseIPDB"]])
        self.assertEqual(connectors, [[]])
        job.delete()
        # the PluginConfig override the runtime

    def test_pipeline_configuration_playbook(self):
        job = Job.objects.create(
            playbooks_to_execute=[self.PLAYBOOK], analyzers_to_execute=["Classic_DNS"]
        )
        configs, analyzers, connectors = job._pipeline_configuration({})
        self.assertIsInstance(configs, list)
        self.assertEqual(1, len(configs))
        self.assertIn("Classic_DNS", configs[0])
        self.assertEqual(configs[0]["Classic_DNS"], {"query_type": "A"})
        self.assertIn("Classic_DNS", analyzers[0])
        self.assertEqual(connectors, [[]])
        job.delete()
