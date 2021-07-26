# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from typing import Tuple
from api_app.connectors_manager.serializers import ConnectorConfigSerializer
from api_app.connectors_manager.models import ConnectorReport
from api_app.models import Job


from .. import CustomAPITestCase, PluginActionViewsetTestCase


class ConnectorAppViewsTestCase(CustomAPITestCase):
    def test_get_connector_config(self):
        response = self.client.get("/api/get_connector_configs")
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.json(), {})
        self.assertDictEqual(
            response.json(), ConnectorConfigSerializer.read_and_verify_config()
        )


class ConnectorActionViewSetTests(PluginActionViewsetTestCase):
    @classmethod
    def setUpClass(cls):
        super(ConnectorActionViewSetTests, cls).setUpClass()

    def setUp(self):
        super(ConnectorActionViewSetTests, self).setUp()

    def init_report(self, status=None) -> Tuple[ConnectorReport, str]:
        _job = Job.objects.create(status="running")
        _report, _ = ConnectorReport.objects.get_or_create(
            **{
                "job_id": _job.id,
                "connector_name": "MISP",
                "status": ConnectorReport.Statuses.PENDING.name
                if status is None
                else status,
                "task_id": "4b77bdd6-d05b-442b-92e8-d53de5d7c1a9",
            }
        )
        return _report, "connector"  # report, plugin_type
