# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from typing import Type

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import PythonModuleBasePaths, ScanMode
from api_app.models import PythonModule
from api_app.playbooks_manager.models import PlaybookConfig
from tests import CustomViewSetTestCase
from tests.api_app.test_views import AbstractConfigViewSetTestCaseMixin


class PlaybookViewTestCase(AbstractConfigViewSetTestCaseMixin, CustomViewSetTestCase):
    URL = "/api/playbook"

    @classmethod
    @property
    def model_class(cls) -> Type[PlaybookConfig]:
        return PlaybookConfig

    def test_list(self):
        super().test_list()

        p = PlaybookConfig.objects.create(
            name="test", type=["ip"], tlp="CLEAR", owner=self.superuser
        )
        response = self.client.get(self.URL)
        result = response.json()
        self.assertEqual(response.status_code, 200, result)
        self.assertIn("count", result)
        self.assertEqual(result["count"], self.model_class.objects.all().count() - 1)

        p.delete()

    def test_delete(self):
        p = PlaybookConfig.objects.create(name="test", type=["ip"], tlp="CLEAR")

        response = self.client.delete(f"{self.URL}/{p.pk}")
        self.assertEqual(response.status_code, 405, response.json())

        p.owner = self.user
        p.save()

        response = self.client.delete(f"{self.URL}/{p.pk}")
        self.assertEqual(response.status_code, 202, response.json())

        p = PlaybookConfig.objects.create(name="test", type=["ip"], tlp="CLEAR")

        self.client.force_authenticate(self.superuser)
        response = self.client.delete(f"{self.URL}/{p.pk}")
        self.assertEqual(response.status_code, 202, response.json())

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
            config={"soft_time_limit": 100, "queue": "default"},
        )

        response = self.client.post(
            self.URL,
            data={
                "name": "TestCreate",
                "description": "test",
                "analyzers": [ac.pk],
                "connectors": [],
                "pivots": [],
                "runtime_configuration": {
                    "analyzers": {"test": {"abc": 3}},
                    "connectors": {},
                    "visualizers": {},
                },
                "scan_mode": ScanMode.FORCE_NEW_ANALYSIS,
                "scan_check_time": None,
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
