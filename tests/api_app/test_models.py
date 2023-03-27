# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.models import Job
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.visualizers_manager.models import VisualizerConfig
from tests import CustomTestCase


class JobTestCase(CustomTestCase):
    PLAYBOOK = "FREE_TO_USE_ANALYZERS"

    def test_merge_configurations(self):
        job = Job.objects.create(
            user=self.user,
        )
        a = AnalyzerConfig.objects.get(name="AbuseIPDB")

        job.playbook_to_execute = PlaybookConfig.objects.get(name=self.PLAYBOOK)
        job.analyzers_to_execute.set([AnalyzerConfig.objects.get(name="AbuseIPDB")])
        config = job._merge_runtime_configuration({"AbuseIPDB": {"param1": 3}}, [a], [])
        a.params["param1"] = {
            "default": 122222,
            "description": "if the file analyzed is a shellcode or not",
            "type": "bool",
        }
        a.save()
        self.assertIn("AbuseIPDB", config)
        self.assertIn("param1", config["AbuseIPDB"])
        self.assertEqual(config["AbuseIPDB"]["param1"], 3)
        config = job._merge_runtime_configuration({"AbuseIPDB": {"param1": 3}}, [a], [])

        self.assertIn("AbuseIPDB", config)
        self.assertIn("param1", config["AbuseIPDB"])
        self.assertEqual(config["AbuseIPDB"]["param1"], 3)
        config = job._merge_runtime_configuration({}, [a], [])
        self.assertIn("AbuseIPDB", config)
        self.assertIn("param1", config["AbuseIPDB"])
        self.assertEqual(config["AbuseIPDB"]["param1"], 122222)
        del a.params["param1"]
        a.save()
        job.delete()

    def test_pipeline_configuration_no_playbook(self):
        job = Job.objects.create(user=self.user)
        job.analyzers_to_execute.set([AnalyzerConfig.objects.get(name="AbuseIPDB")])
        (
            configs,
            analyzers,
            connectors,
            visualizers,
            num_configs,
        ) = job._pipeline_configuration({"AbuseIPDB": {"param1": 3}})
        self.assertEqual(configs, [{"AbuseIPDB": {"param1": 3}}])
        self.assertEqual(
            list(analyzers[0]), list(AnalyzerConfig.objects.filter(name="AbuseIPDB"))
        )
        self.assertEqual(list(connectors[0]), list(ConnectorConfig.objects.none()))
        self.assertEqual(list(visualizers[0]), list(VisualizerConfig.objects.none()))
        self.assertEqual(len(list(num_configs)), 1)
        job.delete()

    def test_pipeline_configuration_playbook(self):
        p = PlaybookConfig.objects.get(name=self.PLAYBOOK)
        p.runtime_configuration["analyzers"]["Classic_DNS"] = {"query_type": "AAA"}
        p.save()
        job = Job.objects.create(
            user=self.user,
        )
        job.playbooks_to_execute.set([PlaybookConfig.objects.get(name=self.PLAYBOOK)])
        job.analyzers_to_execute.set([AnalyzerConfig.objects.get(name="Classic_DNS")])

        (
            configs,
            analyzers,
            connectors,
            visualizers,
            num_configs,
        ) = job._pipeline_configuration({})
        self.assertIsInstance(configs, list)
        self.assertEqual(1, len(configs))
        self.assertIn("Classic_DNS", configs[0])
        self.assertEqual(configs[0]["Classic_DNS"], {"query_type": "AAA"})
        self.assertEqual(
            list(AnalyzerConfig.objects.filter(name="Classic_DNS")), list(analyzers[0])
        )
        self.assertEqual(list(connectors[0]), list(ConnectorConfig.objects.none()))
        self.assertEqual(list(visualizers[0]), list(VisualizerConfig.objects.none()))
        self.assertEqual(len(list(num_configs)), 1)
        job.delete()
