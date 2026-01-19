# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from typing import Type

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import PythonModuleBasePaths, ScanMode
from api_app.models import PythonModule, Tag
from api_app.playbooks_manager.models import PlaybookConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization
from tests import CustomViewSetTestCase
from tests.api_app.test_views import AbstractConfigViewSetTestCaseMixin


class PlaybookConfigViewSetTestCase(
    AbstractConfigViewSetTestCaseMixin, CustomViewSetTestCase
):
    URL = "/api/playbook"

    @classmethod
    @property
    def model_class(cls) -> Type[PlaybookConfig]:
        return PlaybookConfig

    def test_list(self):
        super().test_list()

        self.client.force_authenticate(self.user)
        p = PlaybookConfig.objects.create(
            name="test", type=["ip"], tlp="CLEAR", owner=self.superuser
        )
        response = self.client.get(self.URL)
        result = response.json()
        self.assertEqual(response.status_code, 200, result)
        self.assertIn("count", result)
        self.assertEqual(result["count"], self.model_class.objects.all().count() - 1)

        p.delete()

    def test_update(self):
        plugin = self.model_class.objects.order_by("?").first().name
        response = self.client.patch(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 200, response.json())
        response = self.client.put(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 403, response.json())

    def test_delete(self):
        org1, _ = Organization.objects.get_or_create(name="test")
        m_user, _ = Membership.objects.get_or_create(
            user=self.user, organization=org1, is_owner=False
        )
        m_owner, _ = Membership.objects.get_or_create(
            user=self.superuser, organization=org1, is_owner=True
        )
        p_default = PlaybookConfig.objects.create(
            name="test1", type=["ip"], tlp="CLEAR", owner=None
        )
        p_custom_user = PlaybookConfig.objects.create(
            name="test2", type=["ip"], tlp="CLEAR", owner=m_user.user
        )
        p_custom_org1 = PlaybookConfig.objects.create(
            name="test3",
            type=["ip"],
            tlp="CLEAR",
            owner=m_owner.user,
            for_organization=True,
        )

        self.client.force_authenticate(m_owner.user)
        # 1. owner/admin can't delete a playbook created by an user
        response = self.client.delete(f"{self.URL}/{p_custom_user.pk}")
        self.assertEqual(
            response.status_code, 404
        )  # can't see this playbook in his queryset

        self.client.force_authenticate(m_user.user)
        # 2. user can't delete default playbook
        response = self.client.delete(f"{self.URL}/{p_default.name}")
        self.assertEqual(response.status_code, 403, response.json())
        # 3. user can't delete playbook creted by an owner/admin for the organization
        response = self.client.delete(f"{self.URL}/{p_custom_org1.name}")
        self.assertEqual(response.status_code, 403, response.json())
        # 4. user can delete custom playbook created by itself
        response = self.client.delete(f"{self.URL}/{p_custom_user.name}")
        self.assertEqual(response.status_code, 204)
        # 5. owner/admin can't delete default playbook
        m_user.is_owner = True
        m_user.is_admin = True
        m_user.save()
        response = self.client.delete(f"{self.URL}/{p_default.name}")
        self.assertEqual(response.status_code, 403, response.json())
        # 6. owner/admin can delete playbook creted by an admin of the organization
        response = self.client.delete(f"{self.URL}/{p_custom_org1.name}")
        self.assertEqual(response.status_code, 204)
        # 7. user can't delete a playbook created by an user of another organization
        org2, _ = Organization.objects.get_or_create(name="test2")
        m_user_org2, _ = Membership.objects.get_or_create(
            user=self.admin, organization=org2, is_owner=False
        )
        p_custom_org1 = PlaybookConfig.objects.create(
            name="test4", type=["ip"], tlp="CLEAR", owner=m_user.user
        )
        self.client.force_authenticate(m_user_org2.user)
        response = self.client.delete(f"{self.URL}/{p_custom_org1.name}")
        self.assertEqual(response.status_code, 403)
        # 8. owner/admin can't delete a playbook created by an admin of another org
        m_user_org2.is_owner = True
        m_user_org2.is_admin = True
        m_user_org2.save()
        p_custom_org1.for_organization = True
        p_custom_org1.owner = m_owner.user
        p_custom_org1.save()
        response = self.client.delete(f"{self.URL}/{p_custom_org1.name}")
        self.assertEqual(response.status_code, 403)

    def test_create(self):
        ac, _ = AnalyzerConfig.objects.get_or_create(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.FileAnalyzer.value,
                module="yara_scan.YaraScan",
            ),
            description="test",
            disabled=False,
            type="file",
        )
        tag, _ = Tag.objects.get_or_create(label="testlabel1", color="#FF5733")

        response = self.client.post(
            self.URL,
            data={
                "name": "TestCreate",
                "description": "test",
                "analyzers": [ac.name],
                "connectors": [],
                "pivots": [],
                "runtime_configuration": {
                    "analyzers": {"test": {"abc": 3}},
                    "connectors": {},
                    "visualizers": {},
                },
                "scan_mode": ScanMode.FORCE_NEW_ANALYSIS,
                "scan_check_time": None,
                "tags_labels": [
                    tag.label,
                ],
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.json())
        try:
            pc = PlaybookConfig.objects.get(name="TestCreate")
        except PlaybookConfig.DoesNotExist as e:
            self.fail(e)
        else:
            self.assertEqual(
                pc.runtime_configuration,
                {
                    "analyzers": {"test": {"abc": 3}},
                    "connectors": {},
                    "visualizers": {},
                },
            )
            pc.delete()
        finally:
            ac.delete()

    def test_get(self):
        # 1 - existing visualizer
        self.client.force_authenticate(user=self.user)
        response = self.client.get(f"{self.URL}/Dns")
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            response.json(),
            {
                "analyzers": [
                    "AdGuard",
                    "Classic_DNS",
                    "CloudFlare_DNS",
                    "CloudFlare_Malicious_Detector",
                    "DNS0_EU",
                    "DNS0_EU_Malicious_Detector",
                    "Google_DNS",
                    "Quad9_DNS",
                    "Quad9_Malicious_Detector",
                    "UltraDNS_DNS",
                    "UltraDNS_Malicious_Detector",
                ],
                "connectors": [],
                "description": "Retrieve information from DNS about the domain",
                "disabled": False,
                "for_organization": False,
                "id": 1,
                "is_editable": False,
                "name": "Dns",
                "owner": None,
                "pivots": [],
                "runtime_configuration": {
                    "analyzers": {},
                    "connectors": {},
                    "pivots": {},
                    "visualizers": {},
                },
                "scan_check_time": "1:00:00:00",
                "scan_mode": 2,
                "starting": True,
                "tags": [],
                "tlp": "AMBER",
                "type": ["domain"],
                "visualizers": ["DNS"],
                "weight": 0,
            },
        )
        # 2 - missing playbook
        response = self.client.get(f"{self.URL}/non_existing")
        self.assertEqual(response.status_code, 404, response.content)
        result = response.json()
        self.assertEqual(
            result, {"detail": "No PlaybookConfig matches the given query."}
        )

    def test_get_config(self):
        # 1 - existing playbook
        self.client.force_authenticate(user=self.user)
        response = self.client.get(f"{self.URL}/Dns/plugin_config")
        self.assertEqual(response.status_code, 404, response.content)
