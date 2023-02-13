from django.test import tag
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from api_app.models import PluginConfig

from .. import CustomAPITestCase, User

custom_config_uri = reverse("plugin-config-list")


@tag("plugin_credential")
class PluginCredentialTests(CustomAPITestCase):
    def setUp(self):
        super().setUp()
        PluginConfig.objects.filter(
            config_type=PluginConfig.ConfigType.SECRET
        ).all().delete()
        (
            self.plugin_credential_plugin_credential,
            _,
        ) = PluginConfig.objects.get_or_create(
            **{
                "type": PluginConfig.PluginType.ANALYZER,
                "plugin_name": "GoogleWebRisk",
                "attribute": "api_key_name",
                "value": "test",
                "config_type": PluginConfig.ConfigType.SECRET,
                "owner": self.superuser,
            }
        )

        self.google_safe_browsing_payload = {
            "type": PluginConfig.PluginType.ANALYZER,
            "plugin_name": "GoogleSafebrowsing",
            "attribute": "api_key_name",
            "config_type": PluginConfig.ConfigType.SECRET,
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
        self.assertEqual(response.data[0]["type"], PluginConfig.PluginType.ANALYZER)

    def test_create_credential_superuser(self):
        response = self.client.post(
            custom_config_uri,
            {
                **self.google_safe_browsing_payload,
                "value": '"test"',
            },
            format="json",
        )
        print(response.data)
        self.assertEqual(response.status_code, 201)

        self.assertEqual(response.data["plugin_name"], "GoogleSafebrowsing")
        self.assertEqual(response.data["attribute"], "api_key_name")
        self.assertEqual(response.data["type"], PluginConfig.PluginType.ANALYZER)

        self.assertTrue(
            PluginConfig.objects.filter(config_type=PluginConfig.ConfigType.SECRET)
            .filter(
                **self.google_safe_browsing_payload,
                value="test",
            )
            .exists()
        )
