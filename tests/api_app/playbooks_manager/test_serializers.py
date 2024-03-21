# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework.exceptions import ValidationError

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import ScanMode
from api_app.playbooks_manager.serializers import PlaybookConfigSerializer
from certego_saas.apps.organization.organization import Organization
from tests import CustomTestCase
from tests.mock_utils import MockUpRequest


class PlaybookConfigSerializerTestCase(CustomTestCase):
    def test_create_missing_connectors(self):
        pccs = PlaybookConfigSerializer(
            data={
                "analyzers": [],
                "runtime_configuration": {},
                "pivots": [],
                "name": "test",
                "description": "test",
            },
            context={"request": MockUpRequest(self.user)},
        )
        with self.assertRaises(ValidationError):
            pccs.is_valid(raise_exception=True)

    def test_create_missing_runtime_configuration(self):
        pccs = PlaybookConfigSerializer(
            data={
                "connectors": [],
                "analyzers": [],
                "pivots": [],
                "name": "test",
                "description": "test",
            },
            context={"request": MockUpRequest(self.user)},
        )
        with self.assertRaises(ValidationError):
            pccs.is_valid(raise_exception=True)

    def test_create_missing_pivots(self):
        pccs = PlaybookConfigSerializer(
            data={
                "connectors": [],
                "runtime_configuration": {},
                "analyzers": [],
                "name": "test",
                "description": "test",
            },
            context={"request": MockUpRequest(self.user)},
        )
        with self.assertRaises(ValidationError):
            pccs.is_valid(raise_exception=True)

    def test_create_missing_analyzers(self):
        pccs = PlaybookConfigSerializer(
            data={
                "connectors": [],
                "runtime_configuration": {},
                "pivots": [],
                "name": "test",
                "description": "test",
            },
            context={"request": MockUpRequest(self.user)},
        )
        with self.assertRaises(ValidationError):
            pccs.is_valid(raise_exception=True)

    def test_create(self):
        pccs = PlaybookConfigSerializer(
            data={
                "analyzers": [AnalyzerConfig.objects.first().name],
                "connectors": [],
                "runtime_configuration": {},
                "pivots": [],
                "name": "test",
                "description": "test",
                "scan_mode": ScanMode.FORCE_NEW_ANALYSIS,
                "scan_check_time": None,
            },
            context={"request": MockUpRequest(self.user)},
        )
        pccs.is_valid(raise_exception=True)
        pc = pccs.save()
        pc.delete()

    def test_create_default_user_no_owner(self):
        org = Organization.objects.create(name="test")
        pccs = PlaybookConfigSerializer(
            data={
                "analyzers": [AnalyzerConfig.objects.first().name],
                "connectors": [],
                "runtime_configuration": {},
                "pivots": [],
                "name": "test",
                "description": "test",
                "organization": org,
            },
            context={"request": MockUpRequest(self.user)},
        )
        with self.assertRaises(ValidationError):
            pccs.is_valid(raise_exception=True)
        org.delete()
