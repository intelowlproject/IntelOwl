# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from pathlib import PosixPath
from unittest.mock import patch

from django.conf import settings
from kombu import uuid

from api_app.connectors_manager.classes import Connector
from api_app.connectors_manager.exceptions import ConnectorRunException
from api_app.connectors_manager.models import ConnectorConfig
from api_app.models import Job, PluginConfig
from tests import CustomTestCase


class ConnectorTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
        "api_app/fixtures/0003_connector_pluginconfig.json",
    ]

    def test_health_check(self):
        class MockUpConnector(Connector):
            def run(self) -> dict:
                return {}

        with self.assertRaises(ConnectorRunException):
            MockUpConnector.health_check("test")

        cc = ConnectorConfig.objects.create(
            name="test",
            python_module="misp.MISP",
            description="test",
            disabled=True,
            config={"soft_time_limit": 100, "queue": "default"},
            params={},
            maximum_tlp="WHITE",
        )
        with self.assertRaises(ConnectorRunException):
            MockUpConnector.health_check("test")
        cc.disabled = False
        cc.secrets = {
            "url_key_name": {
                "env_var_key": "TEST_NOT_PRESENT_KEY",
                "type": "str",
                "description": "env_var_key",
                "required": True,
            }
        }
        cc.save()
        with self.assertRaises(ConnectorRunException):
            MockUpConnector.health_check("test")
        pc = PluginConfig.objects.create(
            type="2",
            config_type="2",
            attribute="url_key_name",
            value="https://intelowl.com",
            organization=None,
            owner=self.user,
            plugin_name="test",
        )
        with patch("requests.head"):
            result = MockUpConnector.health_check("test")
        self.assertTrue(result)
        cc.delete()
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
            params={},
            maximum_tlp="WHITE",
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
        )

        subclasses = Connector.all_subclasses()
        for subclass in subclasses:
            print("\n" f"Testing Connector {subclass.__name__}")
            for config in ConnectorConfig.objects.filter(
                python_module=subclass.python_module
            ):
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
