from django.conf import settings
from django.core.files import File
from django.http.request import MultiValueDict, QueryDict
from django.test import TransactionTestCase
from rest_framework.exceptions import ValidationError

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.serializers import (
    ObservableAnalysisSerializer,
    PlaybookFileAnalysisSerializer,
    PlaybookObservableAnalysisSerializer,
    _AbstractJobCreateSerializer,
)
from tests import CustomTestCase
from tests.mock_utils import MockRequest

PLAYBOOK = "FREE_TO_USE_ANALYZERS"


class PlaybookObservableAnalysisSerializerTestCase(TransactionTestCase):

    IP = "1.1.1.1"

    def test_save(self):

        data = {
            "observables": [["ip", self.IP]],
            "playbooks_requested": [PLAYBOOK],
        }

        serializer = PlaybookObservableAnalysisSerializer(data=data, many=True)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as e:
            self.fail(e)

        jobs = serializer.save()
        self.assertEqual(1, len(jobs))
        job = jobs[0]
        self.assertEqual(job.playbooks_to_execute, [PLAYBOOK])


class PlaybookFileAnalysisSerializerTestCase(TransactionTestCase):
    FILE = "file.exe"

    def _read_file_save_job(self, filename: str):
        test_file = f"{settings.PROJECT_LOCATION}/test_files/{filename}"
        self.f = open(test_file, "rb")
        return File(self.f)

    def test_save(self):
        file = self._read_file_save_job(filename=self.FILE)

        data = {
            "files": [file],
            "file_names": [self.FILE],
            "playbooks_requested": [PLAYBOOK],
        }
        qdict = QueryDict("", mutable=True)
        qdict.update(MultiValueDict(data))

        serializer = PlaybookFileAnalysisSerializer(data=qdict, many=True)
        serializer.is_valid(raise_exception=True)
        jobs = serializer.save()
        self.assertEqual(1, len(jobs))
        job = jobs[0]
        self.assertEqual(job.playbooks_to_execute, [PLAYBOOK])


class AbstractJobCreateSerializerTestCase(CustomTestCase):
    def test_filter_analyzers_all(self):
        data = {
            "observable_name": "test.com",
            "observable_classification": "domain",
            "analyzers_requested": [],
            "connectors_requested": [],
            "tlp": "WHITE",
            "runtime_configuration": {},
            "tags_labels": [],
        }
        oass = ObservableAnalysisSerializer(
            data=data, context={"request": MockRequest(self.user)}
        )
        analyzers = _AbstractJobCreateSerializer.filter_analyzers(
            oass, {"tlp": "WHITE", "analyzers_requested": []}
        )
        total = 0
        for analyzer in AnalyzerConfig.objects.all():
            if analyzer.is_runnable(self.user):
                total += 1
        self.assertEqual(len(analyzers), total)

    def test_filter_analyzers_not_runnable(self):
        a = AnalyzerConfig.objects.get(name="Tranco")
        a.disabled = True
        data = {
            "observable_name": "test.com",
            "observable_classification": "domain",
            "analyzers_requested": ["Tranco", "AbuseIPDB"],
            "connectors_requested": [],
            "tlp": "WHITE",
            "runtime_configuration": {},
            "tags_labels": [],
        }
        oass = ObservableAnalysisSerializer(
            data=data, context={"request": MockRequest(self.user)}
        )
        with self.assertRaises(ValidationError):
            _AbstractJobCreateSerializer.filter_analyzers(
                oass, {"tlp": "WHITE", "analyzers_requested": [a]}
            )
        a.disabled = False
        analyzers = _AbstractJobCreateSerializer.filter_analyzers(
            oass, {"tlp": "WHITE", "analyzers_requested": [a]}
        )
        self.assertCountEqual(analyzers, [a])

    def test_filter_analyzers_tlp_not_white(self):
        a = AnalyzerConfig.objects.get(name="Tranco")
        a.leaks_info = True
        data = {
            "observable_name": "test.com",
            "observable_classification": "domain",
            "analyzers_requested": ["Tranco"],
            "connectors_requested": [],
            "tlp": "GREEN",
            "runtime_configuration": {},
            "tags_labels": [],
        }
        oass = ObservableAnalysisSerializer(
            data=data, context={"request": MockRequest(self.user)}
        )
        with self.assertRaises(ValidationError):
            _AbstractJobCreateSerializer.filter_analyzers(
                oass, {"tlp": "GREEN", "analyzers_requested": [a]}
            )

        a.leaks_info = False
        analyzers = _AbstractJobCreateSerializer.filter_analyzers(
            oass, {"tlp": "GREEN", "analyzers_requested": [a]}
        )
        self.assertCountEqual(analyzers, [a])

    def test_filter_analyzers_tlp_red(self):
        a = AnalyzerConfig.objects.get(name="Tranco")
        a.leaks_info = False
        a.external_service = True
        data = {
            "observable_name": "test.com",
            "observable_classification": "domain",
            "analyzers_requested": ["Tranco"],
            "connectors_requested": [],
            "tlp": "RED",
            "runtime_configuration": {},
            "tags_labels": [],
        }
        oass = ObservableAnalysisSerializer(
            data=data, context={"request": MockRequest(self.user)}
        )
        with self.assertRaises(ValidationError):
            _AbstractJobCreateSerializer.filter_analyzers(
                oass, {"tlp": "RED", "analyzers_requested": [a]}
            )
        a.external_service = False
        analyzers = _AbstractJobCreateSerializer.filter_analyzers(
            oass, {"tlp": "RED", "analyzers_requested": [a]}
        )
        self.assertCountEqual(analyzers, [a])
