# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework.exceptions import ValidationError

from api_app.models import Job
from api_app.playbooks_manager.serializers import PlaybookConfigCreateSerializer
from tests import CustomTestCase
from tests.mock_utils import MockUpRequest


class PlaybookConfigSerializerTestCase(CustomTestCase):
    def test_create_wrong_user(self):
        job = Job.objects.create(user=self.superuser, is_sample=True)

        pccs = PlaybookConfigCreateSerializer(
            data={"job": job.pk, "name": "test", "description": "test"},
            context={"request": MockUpRequest(self.user)},
        )
        with self.assertRaises(ValidationError):
            pccs.is_valid(raise_exception=True)

        pccs = PlaybookConfigCreateSerializer(
            data={"job": job.pk, "name": "test", "description": "test"},
            context={"request": MockUpRequest(self.superuser)},
        )
        self.assertTrue(pccs.is_valid())
        pc = pccs.save()
        pc.delete()

        job.delete()
