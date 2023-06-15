# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from typing import Type

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.playbooks_manager.models import PlaybookConfig
from tests import CustomViewSetTestCase
from tests.core.test_views import AbstractConfigViewSetTestCaseMixin


class PlaybookViewTestCase(AbstractConfigViewSetTestCaseMixin, CustomViewSetTestCase):

    URL = "/api/playbook"

    @classmethod
    @property
    def model_class(cls) -> Type[PlaybookConfig]:
        return PlaybookConfig

    def test_create(self):
        ac, _ = AnalyzerConfig.objects.get_or_create(
            name="test",
            python_module="yara.Yara",
            description="test",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            type="observable",
            observable_supported=["ip"],
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
