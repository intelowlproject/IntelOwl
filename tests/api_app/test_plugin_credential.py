# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.test import tag
from rest_framework.reverse import reverse

from api_app.models import PluginConfig

from .. import CustomAPITestCase

custom_config_uri = reverse("plugin-config-list")


@tag("plugin_credential")
class PluginCredentialTests(CustomAPITestCase):
    def setUp(self):
        super().setUp()
        PluginConfig.objects.filter(config_type="2").all().delete()
        (
            self.plugin_credential_plugin_credential,
            _,
        ) = PluginConfig.objects.get_or_create(
            **{
                "type": "1",
                "plugin_name": "GoogleWebRisk",
                "attribute": "api_key_name",
                "value": "test",
                "config_type": "2",
                "owner": self.superuser,
            }
        )

        self.google_safe_browsing_payload = {
            "type": "1",
            "plugin_name": "GoogleSafebrowsing",
            "attribute": "api_key_name",
            "config_type": "2",
        }

    def test_read_credential_superuser(self):
        response = self.client.get(custom_config_uri)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 0, data)

        self.client.force_authenticate(self.superuser)
        response = self.client.get(custom_config_uri)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1, data)
        self.assertEqual(data[0]["plugin_name"], "GoogleWebRisk")
        self.assertEqual(data[0]["attribute"], "api_key_name")
        self.assertEqual(data[0]["type"], "1")

    def test_create_credential_superuser(self):
        response = self.client.post(
            custom_config_uri,
            {
                **self.google_safe_browsing_payload,
                "value": '"test"',
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201)

        self.assertEqual(response.data["plugin_name"], "GoogleSafebrowsing")
        self.assertEqual(response.data["attribute"], "api_key_name")
        self.assertEqual(response.data["type"], "1")

        self.assertTrue(
            PluginConfig.objects.filter(config_type="2")
            .filter(
                **self.google_safe_browsing_payload,
                value="test",
            )
            .exists()
        )
