# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from api_app.analyzers_manager.constants import ObservableTypes
from api_app.connectors_manager.models import ConnectorConfig, ConnectorReport
from api_app.models import Job, PluginConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization

from .. import CustomAPITestCase, PluginActionViewsetTestCase


class ConnectorConfigAPITestCase(CustomAPITestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]
    URL = "/api/connector"

    def test_list(self):
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn("count", result)
        self.assertEqual(result["count"], ConnectorConfig.objects.all().count())
        self.assertIn("results", result)
        self.assertTrue(isinstance(result["results"], list))

        self.client.force_authenticate(None)
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 401)
        self.client.force_authenticate(self.superuser)
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200)

    def test_get(self):
        connector = ConnectorConfig.objects.order_by("?").first().name
        response = self.client.get(f"{self.URL}/{connector}")
        self.assertEqual(response.status_code, 200)

        self.client.force_authenticate(None)
        response = self.client.get(f"{self.URL}/{connector}")
        self.assertEqual(response.status_code, 401)

        self.client.force_authenticate(self.superuser)
        response = self.client.get(f"{self.URL}/{connector}")
        self.assertEqual(response.status_code, 200)

    def test_get_non_existent(self):
        response = self.client.get(f"{self.URL}/NON_EXISTENT")
        self.assertEqual(response.status_code, 404)

    def test_create(self):
        response = self.client.post(self.URL)
        self.assertEqual(response.status_code, 405)

    def test_update(self):
        connector = ConnectorConfig.objects.order_by("?").first().name
        response = self.client.patch(f"{self.URL}/{connector}")
        self.assertEqual(response.status_code, 405)
        self.client.force_authenticate(self.superuser)
        response = self.client.patch(f"{self.URL}/{connector}")
        self.assertEqual(response.status_code, 405)

    def test_delete(self):
        connector = ConnectorConfig.objects.order_by("?").first().name
        response = self.client.delete(f"{self.URL}/{connector}")
        self.assertEqual(response.status_code, 405)
        self.client.force_authenticate(self.superuser)
        response = self.client.delete(f"{self.URL}/{connector}")
        self.assertEqual(response.status_code, 405)

    def test_health_check(self):
        connector: ConnectorConfig = ConnectorConfig.objects.get(name="YETI")
        pc1 = PluginConfig.objects.create(
            parameter=connector.parameters.get(name="api_key_name"),
            value="test",
            for_organization=False,
            owner=None,
        )
        pc2 = PluginConfig.objects.create(
            parameter=connector.parameters.get(name="url_key_name"),
            value="https://test",
            for_organization=False,
            owner=None,
        )
        response = self.client.get(f"{self.URL}/{connector.name}/health_check")
        self.assertEqual(response.status_code, 403)

        self.client.force_authenticate(self.superuser)
        response = self.client.get(f"{self.URL}/{connector.name}/health_check")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn("status", result)
        self.assertTrue(result["status"])
        pc1.delete()
        pc2.delete()

    def test_organization_disable(self):
        connector = "Slack"
        org, _ = Organization.objects.get_or_create(name="test")
        response = self.client.post(f"{self.URL}/{connector}/organization")
        # permission denied
        self.assertEqual(response.status_code, 403, response.json())
        result = response.json()
        self.assertIn("detail", result)
        self.assertEqual(
            result["detail"], "You do not have permission to perform this action."
        )
        m, _ = Membership.objects.get_or_create(
            user=self.user, organization=org, is_owner=False
        )
        response = self.client.post(f"{self.URL}/{connector}/organization")
        # permission denied
        self.assertEqual(response.status_code, 403, response.json())
        result = response.json()
        self.assertIn("detail", result)
        self.assertEqual(
            result["detail"], "You do not have permission to perform this action."
        )

        m.is_owner = True
        m.save()
        an: ConnectorConfig = ConnectorConfig.objects.get(name=connector)
        self.assertFalse(an.disabled_in_organizations.all().exists())
        response = self.client.post(f"{self.URL}/{connector}/organization")
        self.assertEqual(response.status_code, 201)
        self.assertTrue(an.disabled_in_organizations.all().exists())

        response = self.client.post(f"{self.URL}/{connector}/organization")
        self.assertEqual(response.status_code, 400, response.json())
        self.assertEqual(1, an.disabled_in_organizations.all().count())
        result = response.json()
        self.assertIn("errors", result)
        self.assertIn("detail", result["errors"])
        self.assertEqual(
            result["errors"]["detail"], f"Plugin {connector} already disabled"
        )
        an.disabled_in_organizations.set([])
        m.delete()
        org.delete()

    def test_organization_enable(self):
        connector = "Slack"
        org, _ = Organization.objects.get_or_create(name="test")
        response = self.client.delete(f"{self.URL}/{connector}/organization")
        # permission denied
        self.assertEqual(response.status_code, 403, response.json())
        result = response.json()
        self.assertIn("detail", result)
        self.assertEqual(
            result["detail"], "You do not have permission to perform this action."
        )
        m, _ = Membership.objects.get_or_create(
            user=self.user, organization=org, is_owner=False
        )
        response = self.client.delete(f"{self.URL}/{connector}/organization")
        # permission denied
        self.assertEqual(response.status_code, 403, response.json())
        result = response.json()
        self.assertIn("detail", result)
        self.assertEqual(
            result["detail"], "You do not have permission to perform this action."
        )

        m.is_owner = True
        m.save()
        an: ConnectorConfig = ConnectorConfig.objects.get(name=connector)
        self.assertFalse(an.disabled_in_organizations.all().exists())
        response = self.client.delete(f"{self.URL}/{connector}/organization")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(an.disabled_in_organizations.all().exists())
        result = response.json()
        self.assertIn("errors", result)
        self.assertIn("detail", result["errors"])
        self.assertEqual(
            result["errors"]["detail"], f"Plugin {connector} already enabled"
        )

        an.disabled_in_organizations.add(org)
        response = self.client.delete(f"{self.URL}/{connector}/organization")
        self.assertEqual(response.status_code, 202)
        self.assertFalse(an.disabled_in_organizations.all().exists())
        m.delete()
        org.delete()


class ConnectorActionViewSetTests(CustomAPITestCase, PluginActionViewsetTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    @property
    def plugin_type(self):
        return "connector"

    def init_report(self, status: str, user) -> ConnectorReport:
        config = ConnectorConfig.objects.get(name="MISP")
        _job = Job.objects.create(
            user=user,
            status=Job.Status.REPORTED_WITHOUT_FAILS,
            observable_name="8.8.8.8",
            observable_classification=ObservableTypes.IP,
        )
        _job.connectors_to_execute.set([config])
        _report, _ = ConnectorReport.objects.get_or_create(
            **{
                "job_id": _job.id,
                "status": status,
                "config": config,
                "task_id": "4b77bdd6-d05b-442b-92e8-d53de5d7c1a9",
            }
        )
        return _report
