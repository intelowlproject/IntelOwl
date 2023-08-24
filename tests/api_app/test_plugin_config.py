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
        self.ac = AnalyzerConfig.objects.first()
        self.param = Parameter.objects.create(
            python_module=self.ac.python_module,
            name="test",
            is_secret=True,
            required=True,
            type="str",
        )
        self.org0 = Organization.objects.create(name="testorg0")
        self.org1 = Organization.objects.create(name="testorg1")
        self.another_owner = User.objects.create_user(
            username="another_owner",
            email="another_owner@intelowl.com",
            password="test",
        )
        self.another_owner.save()
        self.m0 = Membership.objects.create(
            organization=self.org0, user=self.superuser, is_owner=True
        )
        self.m1 = Membership.objects.create(
            organization=self.org0, user=self.admin, is_owner=False, is_admin=True
        )
        self.m2 = Membership.objects.create(
            organization=self.org1, user=self.user, is_owner=False, is_admin=False
        )
        self.m3 = Membership.objects.create(
            organization=self.org1, user=self.another_owner, is_owner=True
        )
        self.pc0 = PluginConfig.objects.create(
            parameter=self.param,
            analyzer_config=self.ac,
            value="value",
            owner=self.superuser,
            for_organization=True,
        )
        self.pc1 = PluginConfig.objects.create(
            parameter=self.param,
            analyzer_config=self.ac,
            value="value",
            owner=self.another_owner,
            for_organization=True,
        )

    def tearDown(self) -> None:
        self.m0.delete()
        self.m1.delete()
        self.m2.delete()
        self.m3.delete()
        self.pc0.delete()
        self.pc1.delete()
        self.param.delete()
        self.org0.delete()
        self.org1.delete()
        self.another_owner.delete()

    def test_get(self):
        # logged out
        self.client.logout()
        response = self.client.get(f"{custom_config_uri}/{self.pc0.pk}")
        self.assertEqual(response.status_code, 401)
        response = self.client.get(f"{custom_config_uri}/{self.pc1.pk}")
        self.assertEqual(response.status_code, 401)

        # the owner can see the config of own org but not of other orgs
        self.assertTrue(
            PluginConfig.objects.visible_for_user(self.superuser)
            .filter(pk=self.pc0.pk)
            .exists()
        )
        self.assertFalse(
            PluginConfig.objects.visible_for_user(self.superuser)
            .filter(pk=self.pc1.pk)
            .exists()
        )
        self.client.force_authenticate(user=self.superuser)
        response = self.client.get(f"{custom_config_uri}/{self.pc0.pk}")
        self.assertEqual(response.status_code, 200)
        response = self.client.get(f"{custom_config_uri}/{self.pc1.pk}")
        self.assertEqual(response.status_code, 404)

        # also an admin can see the config of own org but not of other orgs
        self.assertTrue(
            PluginConfig.objects.visible_for_user(self.admin)
            .filter(pk=self.pc0.pk)
            .exists()
        )
        self.assertFalse(
            PluginConfig.objects.visible_for_user(self.admin)
            .filter(pk=self.pc1.pk)
            .exists()
        )
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(f"{custom_config_uri}/{self.pc0.pk}")
        self.assertEqual(response.status_code, 200)
        response = self.client.get(f"{custom_config_uri}/{self.pc1.pk}")
        self.assertEqual(response.status_code, 404)

        # a user in the org can see the config of own org but not of other orgs
        self.assertFalse(
            PluginConfig.objects.visible_for_user(self.user)
            .filter(pk=self.pc0.pk)
            .exists()
        )
        self.assertTrue(
            PluginConfig.objects.visible_for_user(self.user)
            .filter(pk=self.pc1.pk)
            .exists()
        )
        self.client.force_authenticate(user=self.user)
        response = self.client.get(f"{custom_config_uri}/{self.pc0.pk}")
        self.assertEqual(response.status_code, 404)
        response = self.client.get(f"{custom_config_uri}/{self.pc1.pk}")
        self.assertEqual(response.status_code, 200)

        # a user outside the org can not see the config
        self.assertFalse(
            PluginConfig.objects.visible_for_user(self.guest)
            .filter(pk=self.pc0.pk)
            .exists()
        )
        self.assertFalse(
            PluginConfig.objects.visible_for_user(self.guest)
            .filter(pk=self.pc1.pk)
            .exists()
        )
        self.client.force_authenticate(user=self.guest)
        response = self.client.get(f"{custom_config_uri}/{self.pc0.pk}")
        self.assertEqual(response.status_code, 404)
        response = self.client.get(f"{custom_config_uri}/{self.pc1.pk}")
        self.assertEqual(response.status_code, 404)

    def test_list(self):
        # logged out
        self.client.logout()
        response = self.client.get(f"{custom_config_uri}")
        self.assertEqual(response.status_code, 401)

        # the owner can see the config of own org
        self.client.force_authenticate(user=self.superuser)
        response = self.client.get(f"{custom_config_uri}")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        # the owner cannot see configs of other orgs (pc1)
        self.assertEqual(1, len(result))
        needle = None
        for obj in result:
            if obj["id"] == self.pc0.pk:
                needle = obj
        self.assertIsNotNone(needle)
        self.assertIn("type", needle)
        self.assertEqual(needle["type"], "1")
        self.assertIn("config_type", needle)
        self.assertEqual(needle["config_type"], "2")
        self.assertIn("plugin_name", needle)
        self.assertEqual(needle["plugin_name"], self.ac.name)
        self.assertIn("organization", needle)
        self.assertEqual(needle["organization"], "testorg0")
        self.assertIn("value", needle)
        self.assertEqual(needle["value"], "value")
        self.assertIn("attribute", needle)
        self.assertEqual(needle["attribute"], "test")

        # an admin can see the config of own org
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(f"{custom_config_uri}")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        # an admin cannot see configs of other orgs (pc1)
        self.assertEqual(1, len(result))
        needle = None
        for obj in result:
            if obj["id"] == self.pc0.pk:
                needle = obj
        self.assertIsNotNone(needle)
        self.assertIn("type", needle)
        self.assertEqual(needle["type"], "1")
        self.assertIn("config_type", needle)
        self.assertEqual(needle["config_type"], "2")
        self.assertIn("plugin_name", needle)
        self.assertEqual(needle["plugin_name"], self.param.analyzer_config.name)
        self.assertIn("organization", needle)
        self.assertEqual(needle["organization"], "testorg0")
        self.assertIn("value", needle)
        self.assertEqual(needle["value"], "value")
        self.assertIn("attribute", needle)
        self.assertEqual(needle["attribute"], "test")

        # a user in the org can see the config with redacted data
        self.client.force_authenticate(user=self.user)
        response = self.client.get(f"{custom_config_uri}")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        # a user cannot see configs of other orgs (pc0)
        self.assertEqual(1, len(result))
        needle = None
        for obj in result:
            if obj["id"] == self.pc1.pk:
                needle = obj
        self.assertIsNotNone(needle)
        self.assertIn("type", needle)
        self.assertEqual(needle["type"], "1")
        self.assertIn("config_type", needle)
        self.assertEqual(needle["config_type"], "2")
        self.assertIn("plugin_name", needle)
        self.assertEqual(needle["plugin_name"], self.param.analyzer_config.name)
        self.assertIn("organization", needle)
        self.assertEqual(needle["organization"], "testorg1")
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
