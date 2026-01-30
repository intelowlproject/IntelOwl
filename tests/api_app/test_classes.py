# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from kombu import uuid

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification, PythonModuleBasePaths
from api_app.classes import Plugin
from api_app.connectors_manager.classes import Connector
from api_app.connectors_manager.models import ConnectorConfig
from api_app.models import Job, PythonModule
from tests import CustomTestCase


class PluginTestCase(CustomTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.an = Analyzable.objects.create(
            name="8.8.8.8",
            classification=Classification.IP,
        )
        self.job, _ = Job.objects.get_or_create(
            user=self.user,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
            analyzable=self.an,
        )
        self.cc, _ = ConnectorConfig.objects.get_or_create(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Connector.value, module="misp.MISP"
            ),
            description="test",
            disabled=False,
            run_on_failure=False,
        )
        self.job.connectors_to_execute.set([self.cc])

    def tearDown(self) -> None:
        self.job.delete()
        self.cc.delete()
        self.an.delete()

    def test_abstract(self):
        with self.assertRaises(TypeError):
            Plugin(self.cc, self.job.pk, {}, str(uuid()))  # noqa

    def test_start_no_errors(self):
        # I can't implement the Plugin class directly because of django installed_apps
        with patch.multiple(Connector, __abstractmethods__=set()), patch.object(Connector, "run") as run:
            run.return_value = {}
            plugin = Connector(self.cc)
            try:
                plugin.start(self.job.pk, {}, uuid())
            except Exception as e:
                self.fail(e)
            else:
                self.assertEqual(plugin.report.status, plugin.report.STATUSES.SUCCESS)

    def test_start_errors(self):
        def raise_error(self):
            raise TypeError("Test")

        with patch.multiple(Connector, __abstractmethods__=set()), patch.multiple(Connector, run=raise_error):
            plugin = Connector(self.cc)
            with self.assertRaises(TypeError):
                plugin.start(self.job.pk, {}, uuid())
            self.assertEqual(plugin.report.status, plugin.report.STATUSES.FAILED)
            self.assertEqual(1, len(plugin.report.errors))
            self.assertEqual("Test", plugin.report.errors[0])

    def test_python_path(self):
        from api_app.analyzers_manager.observable_analyzers.dns.dns_resolvers.classic_dns_resolver import (  # noqa
            ClassicDNSResolver,
        )

        class_ = ClassicDNSResolver
        self.assertEqual(
            class_.python_module.module,
            "dns.dns_resolvers.classic_dns_resolver.ClassicDNSResolver",
        )
