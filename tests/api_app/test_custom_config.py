# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json

from rest_framework.reverse import reverse
from rest_framework.test import APIClient, override_settings

from api_app.models import PluginConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization

from .. import CustomAPITestCase, User

custom_config_uri = reverse("plugin-config-list")
analyze_multiple_observables_uri = reverse("analyze_multiple_observables")
get_analyzer_configs_uri = reverse("get_analyzer_configs")


@override_settings(FORCE_SCHEDULE_JOBS=True)
class CustomConfigTests(CustomAPITestCase):
    def setUp(self):
        super().setUp()
        self.custom_config_su_classic_dns, _ = PluginConfig.objects.get_or_create(
            **{
                "type": PluginConfig.PluginType.ANALYZER,
                "plugin_name": "Classic_DNS",
                "attribute": "query_type",
                "value": "CNAME",
                "owner": self.superuser,
                "config_type": PluginConfig.ConfigType.PARAMETER,
            }
        )
        Organization.create("test_org", self.superuser)
        self.org = Organization.objects.get(name="test_org")
        self.custom_config_org_classic_dns, _ = PluginConfig.objects.get_or_create(
            **{
                "type": PluginConfig.PluginType.ANALYZER,
                "plugin_name": "Classic_DNS",
                "attribute": "query_type",
                "value": "TXT",
                "owner": self.superuser,
                "organization": self.org,
                "config_type": PluginConfig.ConfigType.PARAMETER,
            }
        )

        self.classic_dns_payload = {
            "observables": [["ip", "8.8.8.8"]],
            "analyzers_requested": ["Classic_DNS"],
            "connectors_requested": [],
            "tlp": "WHITE",
            "runtime_configuration": {},
            "tags_labels": [],
        }

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

    def test_self_create_user_config(self):
        response = self.standard_user_client.post(
            custom_config_uri,
            {
                "type": PluginConfig.PluginType.ANALYZER,
                "plugin_name": "Classic_DNS",
                "attribute": "query_type",
                "value": '"CNAME"',
                "config_type": PluginConfig.ConfigType.PARAMETER,
            },
            format="json",
        )
        content = response.json()
        msg = (response, content)
        self.assertEqual(response.status_code, 201, msg=msg)
        try:
            config = PluginConfig.objects.get(
                type=PluginConfig.PluginType.ANALYZER,
                plugin_name="Classic_DNS",
                attribute="query_type",
                owner=self.standard_user,
                config_type=PluginConfig.ConfigType.PARAMETER,
            )
            self.assertEqual(config.value, "CNAME", msg=msg)
        except PluginConfig.DoesNotExist:
            raise Exception(f"CustomConfig not created: {msg}")

    def test_self_create_org_config(self):
        PluginConfig.objects.get(
            type=PluginConfig.PluginType.ANALYZER,
            plugin_name="Classic_DNS",
            attribute="query_type",
            owner=self.superuser,
            organization=self.org,
            config_type=PluginConfig.ConfigType.PARAMETER,
        ).delete()
        response = self.client.post(
            custom_config_uri,
            {
                "type": PluginConfig.PluginType.ANALYZER,
                "plugin_name": "Classic_DNS",
                "attribute": "query_type",
                "value": '"TXT"',
                "organization": self.org.name,
                "config_type": PluginConfig.ConfigType.PARAMETER,
            },
            format="json",
        )
        content = response.json()
        msg = (response, content)
        self.assertEqual(response.status_code, 201, msg=msg)

        try:
            config = PluginConfig.objects.get(
                type=PluginConfig.PluginType.ANALYZER,
                plugin_name="Classic_DNS",
                attribute="query_type",
                owner=self.superuser,
                organization=self.org,
                config_type=PluginConfig.ConfigType.PARAMETER,
            )
            self.assertEqual(config.value, "TXT", msg=msg)
        except PluginConfig.DoesNotExist:
            raise Exception(f"CustomConfig not created: {msg}")

    def test_self_create_incorrect_type_config(self):
        response = self.standard_user_client.post(
            custom_config_uri,
            {
                "type": PluginConfig.PluginType.ANALYZER,
                "plugin_name": "Classic_DNS",
                "attribute": "query_type",
                "value": "99",
                "config_type": PluginConfig.ConfigType.PARAMETER,
            },
            format="json",
        )
        content = response.json()
        msg = (response, content)
        self.assertEqual(response.status_code, 400, msg=msg)
        self.assertFalse(
            PluginConfig.objects.filter(
                **{
                    "type": PluginConfig.PluginType.ANALYZER,
                    "plugin_name": "Classic_DNS",
                    "attribute": "query_type",
                    "owner": self.standard_user,
                    "config_type": PluginConfig.ConfigType.PARAMETER,
                }
            ).exists(),
            msg="CustomConfig created for incorrect type value",
        )

    def test_self_create_invalid_config(self):
        response = self.standard_user_client.post(
            custom_config_uri,
            {
                "type": PluginConfig.PluginType.ANALYZER,
                "plugin_name": "Classic_DNS",
                "attribute": "query_type",
                "value": '"99',
                "config_type": PluginConfig.ConfigType.PARAMETER,
            },
            format="json",
        )
        content = response.json()
        msg = (response, content)
        self.assertEqual(response.status_code, 400, msg=msg)
        self.assertFalse(
            PluginConfig.objects.filter(
                **{
                    "type": PluginConfig.PluginType.ANALYZER,
                    "plugin_name": "Classic_DNS",
                    "attribute": "query_type",
                    "owner": self.standard_user,
                    "config_type": PluginConfig.ConfigType.PARAMETER,
                }
            ).exists(),
            msg="CustomConfig created for invalid value",
        )

    def test_self_update_org_config(self):
        config = PluginConfig.objects.get(
            type=PluginConfig.PluginType.ANALYZER,
            plugin_name="Classic_DNS",
            attribute="query_type",
            owner=self.superuser,
            organization=self.org,
            config_type=PluginConfig.ConfigType.PARAMETER,
        )
        to_value = config.value
        config.value = "ABCD"
        config.save()
        response = self.client.patch(
            f"{custom_config_uri}/{config.id}",
            {
                "type": PluginConfig.PluginType.ANALYZER,
                "plugin_name": "Classic_DNS",
                "attribute": "query_type",
                "value": json.dumps(to_value),
                "organization": self.org.name,
                "config_type": PluginConfig.ConfigType.PARAMETER,
            },
            format="json",
        )
        content = response.json()
        msg = (response, content)
        self.assertEqual(response.status_code, 200, msg=msg)

        try:
            config = PluginConfig.objects.get(
                type=PluginConfig.PluginType.ANALYZER,
                plugin_name="Classic_DNS",
                attribute="query_type",
                owner=self.superuser,
                organization=self.org,
                config_type=PluginConfig.ConfigType.PARAMETER,
            )
            self.assertEqual(config.value, "TXT", msg=msg)
        except PluginConfig.DoesNotExist:
            raise Exception(f"CustomConfig not created: {msg}")

    def test_self_create_unauthorized_org_config(self):
        response = self.standard_user_client.post(
            custom_config_uri,
            {
                "type": PluginConfig.PluginType.ANALYZER,
                "plugin_name": "Classic_DNS",
                "attribute": "query_type",
                "value": '"CNAME"',
                "organization": self.org.name,
                "config_type": PluginConfig.ConfigType.PARAMETER,
            },
            format="json",
        )
        content = response.json()
        msg = (response, content)
        self.assertEqual(response.status_code, 403, msg=msg)

        config = PluginConfig.objects.filter(
            type=PluginConfig.PluginType.ANALYZER,
            plugin_name="Classic_DNS",
            attribute="query_type",
            organization=self.org,
            owner=self.standard_user,
            config_type=PluginConfig.ConfigType.PARAMETER,
        )
        self.assertFalse(config.exists(), msg="Org config created by non-owner")

    def test_custom_config_apply(self):
        response = self.client.get(get_analyzer_configs_uri)
        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIn("Classic_DNS", content)
        self.assertIn("params", content["Classic_DNS"])
        self.assertIn("query_type", content["Classic_DNS"]["params"])
        self.assertIn("value", content["Classic_DNS"]["params"]["query_type"])
        self.assertEqual(
            content["Classic_DNS"]["params"]["query_type"]["value"], "CNAME"
        )
