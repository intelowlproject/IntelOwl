# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from kombu import uuid

from api_app.connectors_manager.classes import Connector
from api_app.connectors_manager.exceptions import ConnectorRunException
from api_app.connectors_manager.models import ConnectorConfig
from api_app.core.models import Parameter
from api_app.models import Job, PluginConfig
from tests import CustomTestCase


class ConnectorTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    def test_health_check(self):
        class MockUpConnector(Connector):
            def run(self) -> dict:
                return {}

        with self.assertRaises(ConnectorRunException):
            MockUpConnector.health_check("test", self.user)

        cc = ConnectorConfig.objects.create(
            name="test",
            python_module="misp.MISP",
            description="test",
            disabled=True,
            config={"soft_time_limit": 100, "queue": "default"},
            maximum_tlp="CLEAR",
        )
        with self.assertRaises(ConnectorRunException):
            MockUpConnector.health_check("test", self.user)
        cc.disabled = False
        param = Parameter.objects.create(
            connector_config=cc,
            name="url_key_name",
            type="str",
            is_secret=True,
            required=True,
        )
        cc.save()
        with self.assertRaises(ConnectorRunException):
            MockUpConnector.health_check("test", self.user)
        pc = PluginConfig.objects.create(
            value="https://intelowl.com",
            owner=self.user,
            parameter=param,
        )
        with patch("requests.head"):
            result = MockUpConnector.health_check("test", self.user)
        self.assertTrue(result)
        cc.delete()
        param.delete()
        pc.delete()

    def test_before_run(self):
        class MockUpConnector(Connector):
            def run(self) -> dict:
                return {}

        job = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            status="failed",
        )
        cc = ConnectorConfig.objects.create(
            name="test",
            python_module="misp.MISP",
            description="test",
            disabled=True,
            config={"soft_time_limit": 100, "queue": "default"},
            maximum_tlp="CLEAR",
            run_on_failure=False,
        )
        with self.assertRaises(ConnectorRunException):
            MockUpConnector(cc, job.pk, {}, uuid()).before_run()
        cc.run_on_failure = True
        cc.save()
        MockUpConnector(cc, job.pk, {}, uuid()).before_run()
        cc.delete()
        job.delete()

    def test_subclasses(self):
        def handler(signum, frame):
            raise TimeoutError("end of time")

        import signal

        signal.signal(signal.SIGALRM, handler)

        job = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            status="reported_without_fails",
            user=self.superuser,
        )

        subclasses = Connector.all_subclasses()
        for subclass in subclasses:
            print("\n" f"Testing Connector {subclass.__name__}")
            for config in ConnectorConfig.objects.filter(
                python_module=subclass.python_module
            ):
                job.connectors_to_execute.set([config])
                timeout_seconds = config.soft_time_limit
                timeout_seconds = min(timeout_seconds, 20)
                print(
                    "\t"
                    f"Testing with config {config.name}"
                    f" for {timeout_seconds} seconds"
                )
                sub = subclass(config, job.pk, {}, uuid())
                signal.alarm(timeout_seconds)
                try:
                    sub.start()
                except Exception as e:
                    self.fail(
                        f"Connector {subclass.__name__}"
                        f" with config {config.name} "
                        f"failed {e}"
                    )
                finally:
                    signal.alarm(0)
        job.delete()
