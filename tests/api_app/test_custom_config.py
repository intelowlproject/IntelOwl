import json
from copy import deepcopy

from rest_framework.reverse import reverse
from rest_framework.test import APIClient, override_settings

from api_app.models import CustomConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization

from .. import CustomAPITestCase, User
from ..celery_tester import task_queue

custom_config_uri = reverse("custom-config-list")
analyze_multiple_observables_uri = reverse("analyze_multiple_observables")
get_analyzer_configs_uri = reverse("get_analyzer_configs")


@override_settings(FORCE_SCHEDULE_JOBS=True)
class CustomConfigTests(CustomAPITestCase):
    def setUp(self):
        super().setUp()
        self.custom_config_su_classic_dns, _ = CustomConfig.objects.get_or_create(
            **{
                "type": CustomConfig.PluginType.ANALYZER,
                "plugin_name": "Classic_DNS",
                "attribute": "query_type",
                "value": "CNAME",
                "owner": self.superuser,
            }
        )
        Organization.create("test_org", self.superuser)
        self.org = Organization.objects.get(name="test_org")
        self.custom_config_org_classic_dns, _ = CustomConfig.objects.get_or_create(
            **{
                "type": CustomConfig.PluginType.ANALYZER,
                "plugin_name": "Classic_DNS",
                "attribute": "query_type",
                "value": "TXT",
                "owner": self.superuser,
                "organization": self.org,
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

    def test_standard_job(self):
        payload = self.classic_dns_payload

        response = self.client.post(
            analyze_multiple_observables_uri, payload, format="json"
        )
        content = response.json()

        celery_task = task_queue.popleft()
        msg = (response, content, celery_task)

        content = content["results"][0]
        if celery_task["analyzers_to_execute"] != content["analyzers_running"]:
            raise Exception(
                f'analyzers_to_execute ({celery_task["analyzers_to_execute"]}) '
                f'!= analyzers_running ({content["analyzers_running"]})'
            )

        self.assertDictEqual(
            celery_task["runtime_configuration"],
            {"Classic_DNS": {"query_type": "CNAME"}},
            msg=msg,
        )

    def test_with_explicit_runtime_config(self):
        payload = deepcopy(self.classic_dns_payload)
        payload["runtime_configuration"] = {"Classic_DNS": {"query_type": "ABCD"}}

        response = self.client.post(
            analyze_multiple_observables_uri, payload, format="json"
        )
        content = response.json()

        celery_task = task_queue.popleft()
        msg = (response, content, celery_task)

        content = content["results"][0]
        if celery_task["analyzers_to_execute"] != content["analyzers_running"]:
            raise Exception(
                f'analyzers_to_execute ({celery_task["analyzers_to_execute"]}) '
                f'!= analyzers_running ({content["analyzers_running"]})'
            )

        self.assertDictEqual(
            celery_task["runtime_configuration"],
            payload["runtime_configuration"],
            msg=msg,
        )

    def test_org_config_for_non_owner(self):
        payload = self.classic_dns_payload

        response = self.standard_user_client.post(
            analyze_multiple_observables_uri, payload, format="json"
        )
        content = response.json()

        celery_task = task_queue.popleft()
        msg = (response, content, celery_task)

        content = content["results"][0]
        if celery_task["analyzers_to_execute"] != content["analyzers_running"]:
            raise Exception(
                f'analyzers_to_execute ({celery_task["analyzers_to_execute"]}) '
                f'!= analyzers_running ({content["analyzers_running"]})'
            )

        self.assertDictEqual(
            celery_task["runtime_configuration"],
            {"Classic_DNS": {"query_type": "TXT"}},
            msg=msg,
        )

    def test_self_create_user_config(self):
        response = self.standard_user_client.post(
            custom_config_uri,
            {
                "type": CustomConfig.PluginType.ANALYZER,
                "plugin_name": "Classic_DNS",
                "attribute": "query_type",
                "value": '"CNAME"',
            },
            format="json",
        )
        content = response.json()
        msg = (response, content)
        self.assertEqual(response.status_code, 201, msg=msg)
        try:
            config = CustomConfig.objects.get(
                type=CustomConfig.PluginType.ANALYZER,
                plugin_name="Classic_DNS",
                attribute="query_type",
                owner=self.standard_user,
            )
            self.assertEqual(config.value, "CNAME", msg=msg)
        except CustomConfig.DoesNotExist:
            raise Exception(f"CustomConfig not created: {msg}")

    def test_self_create_org_config(self):
        CustomConfig.objects.get(
            type=CustomConfig.PluginType.ANALYZER,
            plugin_name="Classic_DNS",
            attribute="query_type",
            owner=self.superuser,
            organization=self.org,
        ).delete()
        response = self.client.post(
            custom_config_uri,
            {
                "type": CustomConfig.PluginType.ANALYZER,
                "plugin_name": "Classic_DNS",
                "attribute": "query_type",
                "value": '"TXT"',
                "organization": self.org.name,
            },
            format="json",
        )
        content = response.json()
        msg = (response, content)
        self.assertEqual(response.status_code, 201, msg=msg)

        try:
            config = CustomConfig.objects.get(
                type=CustomConfig.PluginType.ANALYZER,
                plugin_name="Classic_DNS",
                attribute="query_type",
                owner=self.superuser,
                organization=self.org,
            )
            self.assertEqual(config.value, "TXT", msg=msg)
        except CustomConfig.DoesNotExist:
            raise Exception(f"CustomConfig not created: {msg}")

    def test_self_create_incorrect_type_config(self):
        response = self.standard_user_client.post(
            custom_config_uri,
            {
                "type": CustomConfig.PluginType.ANALYZER,
                "plugin_name": "Classic_DNS",
                "attribute": "query_type",
                "value": "99",
            },
            format="json",
        )
        content = response.json()
        msg = (response, content)
        self.assertEqual(response.status_code, 400, msg=msg)
        self.assertFalse(
            CustomConfig.objects.filter(
                **{
                    "type": CustomConfig.PluginType.ANALYZER,
                    "plugin_name": "Classic_DNS",
                    "attribute": "query_type",
                    "owner": self.standard_user,
                }
            ).exists(),
            msg="CustomConfig created for incorrect type value",
        )

    def test_self_create_invalid_config(self):
        response = self.standard_user_client.post(
            custom_config_uri,
            {
                "type": CustomConfig.PluginType.ANALYZER,
                "plugin_name": "Classic_DNS",
                "attribute": "query_type",
                "value": '"99',
            },
            format="json",
        )
        content = response.json()
        msg = (response, content)
        self.assertEqual(response.status_code, 400, msg=msg)
        self.assertFalse(
            CustomConfig.objects.filter(
                **{
                    "type": CustomConfig.PluginType.ANALYZER,
                    "plugin_name": "Classic_DNS",
                    "attribute": "query_type",
                    "owner": self.standard_user,
                }
            ).exists(),
            msg="CustomConfig created for invalid value",
        )

    def test_self_update_org_config(self):
        config = CustomConfig.objects.get(
            type=CustomConfig.PluginType.ANALYZER,
            plugin_name="Classic_DNS",
            attribute="query_type",
            owner=self.superuser,
            organization=self.org,
        )
        to_value = config.value
        config.value = "ABCD"
        config.save()
        response = self.client.patch(
            f"{custom_config_uri}/{config.id}",
            {
                "type": CustomConfig.PluginType.ANALYZER,
                "plugin_name": "Classic_DNS",
                "attribute": "query_type",
                "value": json.dumps(to_value),
                "organization": self.org.name,
            },
            format="json",
        )
        content = response.json()
        msg = (response, content)
        self.assertEqual(response.status_code, 200, msg=msg)

        try:
            config = CustomConfig.objects.get(
                type=CustomConfig.PluginType.ANALYZER,
                plugin_name="Classic_DNS",
                attribute="query_type",
                owner=self.superuser,
                organization=self.org,
            )
            self.assertEqual(config.value, "TXT", msg=msg)
        except CustomConfig.DoesNotExist:
            raise Exception(f"CustomConfig not created: {msg}")

    def test_self_create_unauthorized_org_config(self):
        response = self.standard_user_client.post(
            custom_config_uri,
            {
                "type": CustomConfig.PluginType.ANALYZER,
                "plugin_name": "Classic_DNS",
                "attribute": "query_type",
                "value": '"CNAME"',
                "organization": self.org.name,
            },
            format="json",
        )
        content = response.json()
        msg = (response, content)
        self.assertEqual(response.status_code, 403, msg=msg)

        config = CustomConfig.objects.filter(
            type=CustomConfig.PluginType.ANALYZER,
            plugin_name="Classic_DNS",
            attribute="query_type",
            organization=self.org,
            owner=self.standard_user,
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
