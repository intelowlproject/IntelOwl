# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from api_app.models import PluginConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization

from .. import CustomAPITestCase

User = get_user_model()


class ViewsTests(CustomAPITestCase):
    def setUp(self):
        super().setUp()
        PluginConfig.objects.all().delete()

    def test_plugins_config_viewset(self):
        org = Organization.create("test_org", self.superuser)

        response = self.client.get("/api/plugin-config", {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertFalse(content)

        # if the user is owner of an org, he should get the org secret
        pc = PluginConfig.objects.create(
            type=1,
            config_type=2,
            attribute="api_key_name",
            value="supersecret",
            organization=org,
            owner=self.superuser,
            plugin_name="AbuseIPDB",
        )
        self.assertEqual(self.client.handler._force_user, org.owner)
        self.assertEqual(pc.owner, org.owner)
        response = self.client.get("/api/plugin-config", {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        first_item = content[0]
        self.assertEqual(first_item["value"], '"supersecret"')

        # second personal item
        secret_owner = PluginConfig(
            type=1,
            config_type=2,
            attribute="api_key_name",
            value="supersecret_user_only",
            organization=None,
            owner=self.superuser,
            plugin_name="AbuseIPDB",
        )
        secret_owner.save()
        response = self.client.get("/api/plugin-config", {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        second_item = content[1]
        self.assertEqual(second_item["value"], '"supersecret_user_only"')

        # if a standard user who does not belong to any org tries to get a secret,
        # they should not find anything
        self.standard_user = User.objects.create_user(
            username="standard_user",
            email="standard_user@intelowl.com",
            password="test",
        )
        self.standard_user.save()
        self.standard_user_client = APIClient()
        self.standard_user_client.force_authenticate(user=self.standard_user)
        response = self.standard_user_client.get(
            "/api/plugin-config", {}, format="json"
        )
        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertFalse(content)

        # if a standard user tries to get the secret of his org,
        # he should have a "redacted" value
        Membership(user=self.standard_user, organization=org, is_owner=False).save()
        response = self.standard_user_client.get(
            "/api/plugin-config", {}, format="json"
        )
        self.assertEqual(response.status_code, 200)
        content = response.json()
        first_item = content[0]
        self.assertEqual(first_item["value"], '"redacted"')
        secret_owner.refresh_from_db()
        self.assertEqual(secret_owner.value, "supersecret_user_only")

        # third superuser secret
        secret_owner = PluginConfig(
            type=1,
            config_type=2,
            attribute="api_key_name",
            value="supersecret_low_privilege",
            organization=None,
            owner=self.standard_user,
            plugin_name="AbuseIPDB",
        )
        secret_owner.save()
        response = self.standard_user_client.get(
            "/api/plugin-config", {}, format="json"
        )
        self.assertEqual(response.status_code, 200)
        content = response.json()
        second_item = content[1]
        self.assertEqual(second_item["value"], '"supersecret_low_privilege"')

        # if there are 2 secrets for different services, the user should get them both
        secret_owner = PluginConfig(
            type=1,
            config_type=2,
            attribute="api_key_name",
            value="supersecret_low_privilege_third",
            organization=None,
            owner=self.standard_user,
            plugin_name="Auth0",
        )
        secret_owner.save()
        response = self.standard_user_client.get(
            "/api/plugin-config", {}, format="json"
        )
        self.assertEqual(response.status_code, 200)
        content = response.json()
        third_item = content[2]
        self.assertEqual(third_item["value"], '"supersecret_low_privilege_third"')
