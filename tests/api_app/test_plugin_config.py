# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib.auth import get_user_model
from rest_framework.reverse import reverse

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.models import Parameter, PluginConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization

from .. import CustomViewSetTestCase

custom_config_uri = reverse("plugin-config-list")
User = get_user_model()


class PluginConfigViewSetTestCase(CustomViewSetTestCase):
    def setUp(self):
        super().setUp()
        self.param = Parameter.objects.create(
            analyzer_config=AnalyzerConfig.objects.first(),
            name="test",
            is_secret=True,
            required=True,
            type="str",
        )
        self.org = Organization.objects.create(name="testorg")
        self.admin = User.objects.create_user(
            username="admin",
            email="admin@intelowl.com",
            password="test",
        )
        self.admin.save()
        self.guest = User.objects.create_user(
            username="guest",
            email="guest@intelowl.com",
            password="test",
        )
        self.guest.save()
        Membership.objects.create(
            organization=self.org, user=self.superuser, is_owner=True
        )
        Membership.objects.create(
            organization=self.org, user=self.admin, is_owner=False, is_admin=True
        )
        Membership.objects.create(
            organization=self.org, user=self.user, is_owner=False, is_admin=False
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
            PluginConfig.objects.visible_for_user(self.superuser)
            .filter(pk=self.pc.pk)
            .exists()
        )

        # logged out
        self.client.logout()
        response = self.client.get(f"{custom_config_uri}/{self.pc.pk}")
        self.assertEqual(response.status_code, 401)

        # the owner can see the config
        self.client.force_authenticate(user=self.superuser)
        response = self.client.get(f"{custom_config_uri}/{self.pc.pk}")
        self.assertEqual(response.status_code, 200)

        # also an admin can see the config
        self.client.force_authenticate(user=self.admin)
        self.assertTrue(
            PluginConfig.objects.visible_for_user(self.admin)
            .filter(pk=self.pc.pk)
            .exists()
        )
        response = self.client.get(f"{custom_config_uri}/{self.pc.pk}")
        self.assertEqual(response.status_code, 200)

        # a user in the org can see the config
        self.assertTrue(
            PluginConfig.objects.visible_for_user(self.user)
            .filter(pk=self.pc.pk)
            .exists()
        )
        self.client.force_authenticate(user=self.user)
        response = self.client.get(f"{custom_config_uri}/{self.pc.pk}")
        self.assertEqual(response.status_code, 200)

        # a user outside the org can not see the config
        self.assertFalse(
            PluginConfig.objects.visible_for_user(self.guest)
            .filter(pk=self.pc.pk)
            .exists()
        )
        self.client.force_authenticate(user=self.guest)
        response = self.client.get(f"{custom_config_uri}/{self.pc.pk}")
        self.assertEqual(response.status_code, 404)

    def test_list(self):
        # logged out
        self.client.logout()
        response = self.client.get(f"{custom_config_uri}")
        self.assertEqual(response.status_code, 401)

        # the owner can see the config
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

        # an admin can see the config
        self.client.force_authenticate(user=self.admin)
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

        # a user in the org can see the config with redacted data
        self.client.force_authenticate(user=self.user)
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
        self.assertEqual(needle["value"], "redacted")
        self.assertIn("attribute", needle)
        self.assertEqual(needle["attribute"], "test")

        # a user outside the org can not see the config
        self.client.force_authenticate(user=self.guest)
        response = self.client.get(f"{custom_config_uri}")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(0, len(result))
