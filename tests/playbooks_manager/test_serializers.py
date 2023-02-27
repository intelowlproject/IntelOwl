from rest_framework.exceptions import ValidationError

from api_app.models import Job
from api_app.playbooks_manager.serializers import PlaybookConfigCreateSerializer
from tests import CustomTestCase


class RequestMockup:
    def __init__(self, user):
        self.user = user


class PlaybookConfigSerializerTestCase(CustomTestCase):
    def test_create(self):
        job = Job.objects.create(user=self.superuser)

        pccs = PlaybookConfigCreateSerializer(
            data={"job": job.pk, "name": "test", "description": "test"},
            context={"request": self.user},
        )
        with self.assertRaises(ValidationError):
            pccs.is_valid(raise_exception=True)

        pccs = PlaybookConfigCreateSerializer(
            data={"job": job.pk, "name": "test", "description": "test"},
            context={"request": self.superuser},
        )
        self.assertTrue(pccs.is_valid())
        pc = pccs.save()
        pc.delete()

        job.delete()
