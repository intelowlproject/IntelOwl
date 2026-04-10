from unittest.mock import MagicMock, patch

from kombu import uuid

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.connectors_manager.connectors.misp import MISP
from api_app.connectors_manager.models import ConnectorConfig, ConnectorReport
from api_app.models import Job, Parameter, PluginConfig
from tests import CustomTestCase


class MISPConnectorTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    @staticmethod
    def _get_misp_config():
        return ConnectorConfig.objects.get(name="MISP")

    @staticmethod
    def _create_plugin_configs(config):
        pcs = []
        for name in ("url_key_name", "api_key_name"):
            param = Parameter.objects.get(python_module=config.python_module, name=name)
            pc = PluginConfig.objects.create(
                parameter=param,
                value="https://misp.test" if "url" in name else "test-api-key",
                for_organization=False,
                owner=None,
                connector_config=config,
            )
            pcs.append(pc)
        return pcs

    def _setup_job(self):
        config = self._get_misp_config()
        pcs = self._create_plugin_configs(config)
        analyzable = Analyzable.objects.create(name="8.8.8.8", classification=Classification.IP)
        job = Job.objects.create(
            analyzable=analyzable,
            user=self.superuser,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS.value,
        )
        job.connectors_to_execute.set([config])
        return job, config, pcs

    @staticmethod
    def _cleanup(job, config, pcs):
        try:
            ConnectorReport.objects.get(job=job, config=config).delete()
        except ConnectorReport.DoesNotExist:
            pass
        analyzable = job.analyzable
        job.delete()
        analyzable.delete()
        for pc in pcs:
            pc.delete()

    @patch("api_app.connectors_manager.connectors.misp.MockPyMISP")
    @patch("api_app.connectors_manager.connectors.misp.pymisp.PyMISP")
    def test_bulk_add_event_called_once(self, mock_pymisp_cls, mock_misp_cls):
        """
        run() must call add_event exactly once with all attributes already
        attached to the event object. add_attribute on the MISP instance
        must never be called (that was the old N+1 pattern).
        """
        mock_instance = MagicMock()
        mock_pymisp_cls.return_value = mock_instance
        mock_misp_cls.return_value = mock_instance

        mock_event = MagicMock()
        mock_event.id = 42
        mock_instance.add_event.return_value = mock_event
        mock_instance.get_event.return_value = {"Event": {"id": 42}}

        job, config, pcs = self._setup_job()
        try:
            connector = MISP(config)
            connector.start(job.pk, {}, uuid())

            report = ConnectorReport.objects.get(job=job, config=config)
            self.assertEqual(report.status, ConnectorReport.STATUSES.SUCCESS)

            mock_instance.add_event.assert_called_once()
            mock_instance.add_attribute.assert_not_called()

            event_arg = mock_instance.add_event.call_args[0][0]
            self.assertGreaterEqual(len(event_arg.attributes), 1)
        finally:
            self._cleanup(job, config, pcs)

    @patch("api_app.connectors_manager.connectors.misp.MockPyMISP")
    @patch("api_app.connectors_manager.connectors.misp.pymisp.PyMISP")
    def test_all_attributes_present_on_event(self, mock_pymisp_cls, mock_misp_cls):
        """
        The event sent to MISP must contain the base attribute and the
        link attribute — all in one shot.
        """
        mock_instance = MagicMock()
        mock_pymisp_cls.return_value = mock_instance
        mock_misp_cls.return_value = mock_instance

        mock_event = MagicMock()
        mock_event.id = 99
        mock_instance.add_event.return_value = mock_event
        mock_instance.get_event.return_value = {"Event": {"id": 99}}

        job, config, pcs = self._setup_job()
        try:
            connector = MISP(config)
            connector.start(job.pk, {}, uuid())

            event_arg = mock_instance.add_event.call_args[0][0]
            attr_types = [a.type for a in event_arg.attributes]

            self.assertIn("ip-src", attr_types)
            self.assertIn("link", attr_types)
        finally:
            self._cleanup(job, config, pcs)

    @patch("api_app.connectors_manager.connectors.misp.MockPyMISP")
    @patch("api_app.connectors_manager.connectors.misp.pymisp.PyMISP")
    def test_add_event_failure_marks_report_failed(self, mock_pymisp_cls, mock_misp_cls):
        """
        If add_event raises, the connector report status must be FAILED.
        """
        mock_instance = MagicMock()
        mock_pymisp_cls.return_value = mock_instance
        mock_misp_cls.return_value = mock_instance
        mock_instance.add_event.side_effect = Exception("MISP unreachable")

        job, config, pcs = self._setup_job()
        try:
            connector = MISP(config)
            try:
                connector.start(job.pk, {}, uuid())
            except Exception:
                pass

            report = ConnectorReport.objects.get(job=job, config=config)
            self.assertEqual(report.status, ConnectorReport.STATUSES.FAILED)
        finally:
            self._cleanup(job, config, pcs)
