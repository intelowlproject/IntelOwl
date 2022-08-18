from django.test import tag
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from api_app.models import CustomConfig, PluginCredential
from intel_owl.secrets import get_secret

from .. import CustomAPITestCase, User

custom_config_uri = reverse("plugin-credential-list")


@tag("plugin_credential")
class PluginCredentialTests(CustomAPITestCase):
    def setUp(self):
        super().setUp()
        PluginCredential.objects.all().delete()
        (
            self.plugin_credential_plugin_credential,
            _,
        ) = PluginCredential.objects.get_or_create(
            **{
                "type": CustomConfig.PluginType.ANALYZER,
                "plugin_name": "GoogleWebRisk",
                "attribute": "api_key_name",
                "value": "test",
            }
        )

        self.google_safe_browsing_payload = {
            "type": CustomConfig.PluginType.ANALYZER,
            "plugin_name": "GoogleSafebrowsing",
            "attribute": "api_key_name",
            "value": "test",
        }

        # create user
        self.standard_user = User.objects.create_user(
            username="standard_user",
            email="standard_user@intelowl.com",
            password="test",
        )
        self.standard_user_client = APIClient()
        self.standard_user_client.force_authenticate(user=self.standard_user)

    def test_read_credential_superuser(self):
        response = self.client.get(custom_config_uri)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)

        self.assertEqual(response.data[0]["plugin_name"], "GoogleWebRisk")
        self.assertEqual(response.data[0]["attribute"], "api_key_name")
        self.assertEqual(response.data[0]["type"], CustomConfig.PluginType.ANALYZER)

        # Check that secret values are not returned
        self.assertNotIn("value", response.data[0])

    def test_read_credential_unauthorized_user(self):
        response = self.standard_user_client.get(custom_config_uri)
        self.assertEqual(response.status_code, 403)

    def test_create_credential_superuser(self):
        response = self.client.post(
            custom_config_uri, self.google_safe_browsing_payload
        )
        self.assertEqual(response.status_code, 201)

        self.assertEqual(response.data["plugin_name"], "GoogleSafebrowsing")
        self.assertEqual(response.data["attribute"], "api_key_name")
        self.assertEqual(response.data["type"], CustomConfig.PluginType.ANALYZER)

        # Check that secret values are not returned
        self.assertNotIn("value", response.data)

        self.assertTrue(
            PluginCredential.objects.filter(
                **self.google_safe_browsing_payload
            ).exists()
        )

    def test_get_secret(self):
        value = get_secret(
            self.plugin_credential_plugin_credential.attribute,
            plugin_type=self.plugin_credential_plugin_credential.type,
            plugin_name=self.plugin_credential_plugin_credential.plugin_name,
        )
        self.assertEqual(value, self.plugin_credential_plugin_credential.value)
