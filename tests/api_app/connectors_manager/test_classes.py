# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

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
        with patch("requests.head"):
            result = MockUpConnector(cc).health_check(self.user)
        self.assertTrue(result)
        cc.disabled = False
        cc.save()
        result = MockUpConnector(cc).health_check(self.user)
        self.assertTrue(result)
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
        def handler(signum, frame):
            raise TimeoutError("end of time")

        import signal

        signal.signal(signal.SIGALRM, handler)
        an1 = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        job = Job.objects.create(
            analyzable=an1,
            status="reported_without_fails",
            user=self.superuser,
        )

        subclasses = Connector.all_subclasses()
        for subclass in subclasses:
            print(f"\nTesting Connector {subclass.__name__}")
            configs = ConnectorConfig.objects.filter(python_module=subclass.python_module)
            if not configs.exists():
                self.fail(f"There is a python module {subclass.python_module} without any configuration")
            for config in configs:
                job.connectors_to_execute.set([config])
                timeout_seconds = config.soft_time_limit
                timeout_seconds = min(timeout_seconds, 20)
                print(f"\tTesting with config {config.name} for {timeout_seconds} seconds")
                sub = subclass(
                    config,
                )
                signal.alarm(timeout_seconds)
                try:
                    sub.start(job.pk, {}, uuid())
                except Exception as e:
                    self.fail(f"Connector {subclass.__name__} with config {config.name} failed {e}")
                finally:
                    signal.alarm(0)
        job.delete()
        an1.delete()
