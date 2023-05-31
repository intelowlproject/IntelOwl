# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework.reverse import reverse

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.core.models import Parameter
from api_app.models import PluginConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization

from .. import CustomAPITestCase

custom_config_uri = reverse("plugin-config-list")


class PluginConfigViewSetTestCase(CustomAPITestCase):
    def setUp(self):
        super().setUp()
        self.param = Parameter.objects.create(
            analyzer_config=AnalyzerConfig.objects.first(),
            name="test",
            is_secret=True,
            required=True,
        )
        self.org = Organization.objects.create(name="testorg")
        Membership.objects.create(
            organization=self.org, user=self.superuser, is_owner=True
        )
        self.pc = PluginConfig.objects.create(
            parameter=self.param,
            value="value",
            owner=self.superuser,
            for_organization=True,
        )

    def tearDown(self) -> None:
        self.pc.delete()
        self.param.delete()
        self.org.delete()

    def test_get(self):
        self.assertTrue(
            PluginConfig.visible_for_user(self.superuser).filter(pk=self.pc.pk).exists()
        )
        response = self.client.get(f"{custom_config_uri}/{self.pc.pk}")
        self.assertEqual(response.status_code, 404)
        self.client.force_authenticate(user=self.superuser)
        response = self.client.get(f"{custom_config_uri}/{self.pc.pk}")
        self.assertEqual(response.status_code, 200)

    def test_list(self):
        response = self.client.get(f"{custom_config_uri}")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(0, len(result))
        self.client.force_authenticate(user=self.superuser)
        response = self.client.get(f"{custom_config_uri}")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        needle = None
        for obj in result:
            if obj["id"] == self.pc.pk:
                needle = obj
        self.assertIsNotNone(needle)
        self.assertIn("type", needle)
        self.assertEqual(needle["type"], "1")
        self.assertIn("config_type", needle)
        self.assertEqual(needle["config_type"], "2")
        self.assertIn("plugin_name", needle)
        self.assertEqual(needle["plugin_name"], self.param.analyzer_config.name)
        self.assertIn("organization", needle)
        self.assertEqual(needle["organization"], "testorg")
        self.assertIn("value", needle)
        self.assertEqual(needle["value"], "value")

        self.assertIn("attribute", needle)
        self.assertEqual(needle["attribute"], "test")
