import json
import os

from django.test import tag
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from api_app.models import OrganizationPluginState, PluginConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization

from .. import CustomAPITestCase, User

plugin_state_viewer_uri = reverse("plugin_state_viewer")


@tag("plugin_state")
class PluginStateTests(CustomAPITestCase):
    def setUp(self):
        super().setUp()
        self.analyze_observable_ip_data = {
            "observable_name": os.environ.get("TEST_IP", "8.8.8.8"),
            "analyzers_requested": [
                "Classic_DNS",
            ],
            "observable_classification": "ip",
        }

        Organization.create("test_org", self.superuser)
        self.org = Organization.objects.get(name="test_org")

        # create user
        self.standard_user = User.objects.create_user(
            username="standard_user",
            email="standard_user@intelowl.com",
            password="test",
        )
        self.standard_user_client = APIClient()
        self.standard_user_client.force_authenticate(user=self.standard_user)
        Membership.objects.create(
            user=self.standard_user,
            organization=self.org,
        )

        OrganizationPluginState.objects.create(
            organization=self.org,
            plugin_name="Classic_DNS",
            disabled=True,
            type=PluginConfig.PluginType.ANALYZER,
        )

    def test_disable_plugin(self):
        response = self.client.post(
            f"{plugin_state_viewer_uri}"
            f"{PluginConfig.PluginType.ANALYZER}/CloudFlare_DNS/"
        )
        self.assertEqual(response.status_code, 201)
        self.assertTrue(
            OrganizationPluginState.objects.get(
                organization=self.org,
                plugin_name="CloudFlare_DNS",
                type=PluginConfig.PluginType.ANALYZER,
            ).disabled
        )
        OrganizationPluginState.objects.get(
            organization=self.org,
            plugin_name="CloudFlare_DNS",
            type=PluginConfig.PluginType.ANALYZER,
        ).delete()

    def test_enable_plugin(self):
        OrganizationPluginState.objects.create(
            organization=self.org,
            plugin_name="CloudFlare_DNS",
            disabled=True,
            type=PluginConfig.PluginType.ANALYZER,
        )
        response = self.client.delete(
            f"{plugin_state_viewer_uri}"
            f"{PluginConfig.PluginType.ANALYZER}/CloudFlare_DNS/"
        )
        self.assertEqual(response.status_code, 201)
        self.assertFalse(
            OrganizationPluginState.objects.filter(
                organization=self.org,
                plugin_name="CloudFlare_DNS",
                disabled=True,
                type=PluginConfig.PluginType.ANALYZER,
            ).exists()
        )
        OrganizationPluginState.objects.get(
            organization=self.org,
            plugin_name="Classic_DNS",
            type=PluginConfig.PluginType.ANALYZER,
        ).delete()

    def test_disable_plugin_forbidden(self):
        response = self.standard_user_client.post(
            f"{plugin_state_viewer_uri}"
            f"{PluginConfig.PluginType.ANALYZER}/CloudFlare_DNS/"
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(
            OrganizationPluginState.objects.filter(
                organization=self.org,
                plugin_name="CloudFlare_DNS",
                disabled=True,
                type=PluginConfig.PluginType.ANALYZER,
            ).exists()
        )

    def test_enable_plugin_forbidden(self):
        OrganizationPluginState.objects.create(
            organization=self.org,
            plugin_name="CloudFlare_DNS",
            disabled=True,
            type=PluginConfig.PluginType.ANALYZER,
        )
        response = self.standard_user_client.delete(
            f"{plugin_state_viewer_uri}"
            f"{PluginConfig.PluginType.ANALYZER}/CloudFlare_DNS/"
        )
        self.assertEqual(response.status_code, 403)
        self.assertTrue(
            OrganizationPluginState.objects.get(
                organization=self.org,
                plugin_name="CloudFlare_DNS",
                type=PluginConfig.PluginType.ANALYZER,
            ).disabled
        )
        OrganizationPluginState.objects.get(
            organization=self.org,
            plugin_name="Classic_DNS",
            type=PluginConfig.PluginType.ANALYZER,
        ).delete()

    def test_run_disabled_plugin(self):
        data = self.analyze_observable_ip_data.copy()

        response = self.client.post("/api/analyze_observable", data, format="json")
        content = response.json()
        msg = (response.status_code, content)
        self.assertEqual(response.status_code, 400, msg=msg)
        self.assertIn("No Analyzers can be run after filtering.", json.dumps(content))
