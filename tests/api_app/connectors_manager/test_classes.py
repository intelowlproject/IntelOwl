# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from django.conf import settings
from kombu import uuid

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.choices import Classification, PythonModuleBasePaths
from api_app.connectors_manager.classes import Connector
from api_app.connectors_manager.exceptions import ConnectorRunException
from api_app.connectors_manager.models import ConnectorConfig
from api_app.models import Job, Parameter, PluginConfig, PythonModule
from tests import CustomTestCase


class ConnectorTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    def test_health_check(self):
        pm = PythonModule.objects.get(base_path=PythonModuleBasePaths.Connector.value, module="misp.MISP")
        cc = ConnectorConfig.objects.create(
            name="test",
            python_module=pm,
            description="test",
            disabled=True,
            maximum_tlp="CLEAR",
        )

        class MockUpConnector(Connector):
            def run(self) -> dict:
                return {}

        with self.assertRaises(NotImplementedError):
            MockUpConnector(cc).health_check(self.user)
        pc = PluginConfig.objects.create(
            value="https://intelowl.com",
            owner=self.user,
            parameter=Parameter.objects.get(name="url_key_name", python_module=pm),
            connector_config=cc,
        )

        with patch("requests.head") as mock_head:
            mock_head.return_value.status_code = 200
            status, _ = MockUpConnector(cc).health_check(self.user)
            self.assertTrue(status)
            cc.disabled = False
            cc.save()
            status, _ = MockUpConnector(cc).health_check(self.user)
            self.assertTrue(status)

        cc.delete()
        pc.delete()

    def test_before_run(self):
        class MockUpConnector(Connector):
            def run(self) -> dict:
                return {}

        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        job = Job.objects.create(
            analyzable=an,
            status=Job.STATUSES.CONNECTORS_RUNNING.value,
        )
        AnalyzerReport.objects.create(
            report={},
            job=job,
            config=AnalyzerConfig.objects.first(),
            status=AnalyzerReport.STATUSES.FAILED.value,
            task_id=str(uuid()),
            parameters={},
        )
        cc = ConnectorConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Connector.value, module="misp.MISP"
            ),
            description="test",
            disabled=True,
            maximum_tlp="CLEAR",
            run_on_failure=False,
        )
        with self.assertRaises(ConnectorRunException):
            muc = MockUpConnector(cc)
            muc.job_id = job.pk
            muc.before_run()
        cc.run_on_failure = True
        cc.save()
        muc = MockUpConnector(cc)
        muc.job_id = job.pk
        muc.before_run()
        cc.delete()
        job.delete()
        an.delete()

    def test_subclasses(self):
        subclasses = Connector.all_subclasses()
        for subclass in subclasses:
            configs = ConnectorConfig.objects.filter(python_module=subclass.python_module)
            if not configs.exists():
                self.fail(f"There is a python module {subclass.python_module} without any configuration")

    def test_before_run_partial_failure(self):
        # run_on_failure=False + partial failure (mix of FAILED and SUCCESS) should raise ConnectorRunException
        class MockUpConnector(Connector):
            def run(self) -> dict:
                return {}

        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        job = Job.objects.create(
            analyzable=an,
            status=Job.STATUSES.CONNECTORS_RUNNING.value,
        )
        AnalyzerReport.objects.create(
            report={},
            job=job,
            config=AnalyzerConfig.objects.first(),
            status=AnalyzerReport.STATUSES.FAILED.value,
            task_id=str(uuid()),
            parameters={},
        )
        AnalyzerReport.objects.create(
            report={},
            job=job,
            config=AnalyzerConfig.objects.last(),
            status=AnalyzerReport.STATUSES.SUCCESS.value,
            task_id=str(uuid()),
            parameters={},
        )
        cc = ConnectorConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Connector.value, module="misp.MISP"
            ),
            description="test",
            disabled=True,
            maximum_tlp="CLEAR",
            run_on_failure=False,
        )
        with self.assertRaises(ConnectorRunException):
            muc = MockUpConnector(cc)
            muc.job_id = job.pk
            muc.before_run()
        cc.delete()
        job.delete()
        an.delete()


class CTIConnectorTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    @staticmethod
    def _create_job(name, classification):
        an = Analyzable.objects.create(
            name=name,
            classification=classification,
        )
        job = Job.objects.create(
            analyzable=an,
            status=Job.STATUSES.CONNECTORS_RUNNING.value,
        )
        return job, an

    @staticmethod
    def _create_cti_connector(job):
        from api_app.connectors_manager.classes import CTIConnector

        pm = PythonModule.objects.get(base_path=PythonModuleBasePaths.Connector.value, module="misp.MISP")
        cc = ConnectorConfig.objects.create(
            name="test_cti",
            python_module=pm,
            description="test cti connector",
            disabled=True,
            maximum_tlp="CLEAR",
        )

        class MockCTIConnector(CTIConnector):
            def run(self) -> dict:
                return {}

        connector = MockCTIConnector(cc)
        connector.job_id = job.pk
        return connector, cc

    def test_observable_name_domain(self):
        job, an = self._create_job("example.com", Classification.DOMAIN)
        connector, cc = self._create_cti_connector(job)

        self.assertEqual(connector.observable_name, "example.com")

        cc.delete()
        job.delete()
        an.delete()

    def test_observable_value_observable(self):
        job, an = self._create_job("8.8.8.8", Classification.IP)
        connector, cc = self._create_cti_connector(job)

        self.assertEqual(connector.observable_value, "8.8.8.8")

        cc.delete()
        job.delete()
        an.delete()

    def test_classification_ip(self):
        job, an = self._create_job("8.8.8.8", Classification.IP)
        connector, cc = self._create_cti_connector(job)

        self.assertEqual(connector.classification, Classification.IP)

        cc.delete()
        job.delete()
        an.delete()

    def test_classification_domain(self):
        job, an = self._create_job("example.com", Classification.DOMAIN)
        connector, cc = self._create_cti_connector(job)

        self.assertEqual(connector.classification, Classification.DOMAIN)

        cc.delete()
        job.delete()
        an.delete()

    def test_hash_type_md5(self):
        md5_hash = "d" * 32
        job, an = self._create_job(md5_hash, Classification.HASH)
        connector, cc = self._create_cti_connector(job)

        self.assertEqual(connector.hash_type, "md5")

        cc.delete()
        job.delete()
        an.delete()

    def test_hash_type_sha256(self):
        sha256_hash = "a" * 64
        job, an = self._create_job(sha256_hash, Classification.HASH)
        connector, cc = self._create_cti_connector(job)

        self.assertEqual(connector.hash_type, "sha-256")

        cc.delete()
        job.delete()
        an.delete()

    def test_hash_type_none_for_non_hash(self):
        job, an = self._create_job("8.8.8.8", Classification.IP)
        connector, cc = self._create_cti_connector(job)

        self.assertIsNone(connector.hash_type)

        cc.delete()
        job.delete()
        an.delete()

    def test_ip_version_v4(self):
        job, an = self._create_job("8.8.8.8", Classification.IP)
        connector, cc = self._create_cti_connector(job)

        self.assertEqual(connector.ip_version, 4)

        cc.delete()
        job.delete()
        an.delete()

    def test_ip_version_v6(self):
        job, an = self._create_job("::1", Classification.IP)
        connector, cc = self._create_cti_connector(job)

        self.assertEqual(connector.ip_version, 6)

        cc.delete()
        job.delete()
        an.delete()

    def test_ip_version_none_for_non_ip(self):
        job, an = self._create_job("example.com", Classification.DOMAIN)
        connector, cc = self._create_cti_connector(job)

        self.assertIsNone(connector.ip_version)

        cc.delete()
        job.delete()
        an.delete()

    def test_analysis_url(self):
        job, an = self._create_job("example.com", Classification.DOMAIN)
        connector, cc = self._create_cti_connector(job)

        expected = f"{settings.WEB_CLIENT_URL}/jobs/{job.pk}"
        self.assertEqual(connector.analysis_url, expected)

        cc.delete()
        job.delete()
        an.delete()

    def test_tag_labels(self):
        from api_app.models import Tag

        job, an = self._create_job("example.com", Classification.DOMAIN)
        connector, cc = self._create_cti_connector(job)

        tag1 = Tag.objects.create(label="test-tag-1", color="#FF0000")
        tag2 = Tag.objects.create(label="test-tag-2", color="#00FF00")
        job.tags.add(tag1, tag2)

        labels = connector.tag_labels
        self.assertIn("test-tag-1", labels)
        self.assertIn("test-tag-2", labels)
        self.assertEqual(len(labels), 2)

        job.tags.clear()
        tag1.delete()
        tag2.delete()
        cc.delete()
        job.delete()
        an.delete()

    def test_enrichment_without_data_model(self):
        job, an = self._create_job("example.com", Classification.DOMAIN)
        connector, cc = self._create_cti_connector(job)

        # Job has no data_model set -- all enrichment should be None/empty
        self.assertFalse(connector.has_data_model)
        self.assertIsNone(connector.evaluation)
        self.assertIsNone(connector.malware_family)
        self.assertIsNone(connector.kill_chain_phase)
        self.assertIsNone(connector.reliability)
        self.assertEqual(connector.related_threats, [])
        self.assertEqual(connector.data_model_tags, [])
        self.assertEqual(connector.external_references, [])
        self.assertEqual(connector.get_enrichment_summary(), {})

        cc.delete()
        job.delete()
        an.delete()

    def test_enrichment_with_data_model(self):
        from api_app.data_model_manager.models import DomainDataModel

        job, an = self._create_job("example.com", Classification.DOMAIN)
        connector, cc = self._create_cti_connector(job)

        # Create a real data model and attach to job
        dm = DomainDataModel.objects.create(
            evaluation="malicious",
            malware_family="emotet",
            kill_chain_phase="delivery",
            reliability=8,
            related_threats=["threat1", "threat2"],
            tags=["malware", "phishing"],
            external_references=["https://example.com/report"],
        )
        job.data_model = dm
        job.save()

        # Clear the cached_property so it re-reads
        if "_merged_data_model" in connector.__dict__:
            del connector.__dict__["_merged_data_model"]
        # Also clear the cached _job property
        if "_job" in connector.__dict__:
            del connector.__dict__["_job"]

        self.assertTrue(connector.has_data_model)
        self.assertEqual(connector.evaluation, "malicious")
        self.assertEqual(connector.malware_family, "emotet")
        self.assertEqual(connector.kill_chain_phase, "delivery")
        self.assertEqual(connector.reliability, 8)
        self.assertIn("threat1", connector.related_threats)
        self.assertIn("threat2", connector.related_threats)
        self.assertIn("malware", connector.data_model_tags)
        self.assertIn("phishing", connector.data_model_tags)
        self.assertIn("https://example.com/report", connector.external_references)

        summary = connector.get_enrichment_summary()
        self.assertEqual(summary["evaluation"], "malicious")
        self.assertEqual(summary["malware_family"], "emotet")
        self.assertEqual(summary["kill_chain_phase"], "delivery")
        self.assertEqual(summary["reliability"], 8)

        dm.delete()
        cc.delete()
        job.delete()
        an.delete()

    def test_enrichment_generic_classification(self):
        # Generic classification has no data model, enrichment should be None/empty
        job, an = self._create_job("some-random-text", Classification.GENERIC)
        connector, cc = self._create_cti_connector(job)

        self.assertFalse(connector.has_data_model)
        self.assertIsNone(connector.evaluation)
        self.assertEqual(connector.get_enrichment_summary(), {})

        cc.delete()
        job.delete()
        an.delete()
