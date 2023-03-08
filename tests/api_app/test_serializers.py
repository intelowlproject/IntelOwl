from unittest.mock import patch

from django.conf import settings
from django.core.files import File
from django.http.request import MultiValueDict, QueryDict
from django.test import TransactionTestCase
from rest_framework.exceptions import ValidationError

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.serializers import (
    ObservableAnalysisSerializer,
    PlaybookFileAnalysisSerializer,
    PlaybookObservableAnalysisSerializer,
    _AbstractJobCreateSerializer,
)
from api_app.visualizers_manager.models import VisualizerConfig
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
        oass = ObservableAnalysisSerializer(
            data={}, context={"request": MockRequest(self.user)}
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
        oass = ObservableAnalysisSerializer(
            data={}, context={"request": MockRequest(self.user)}
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
        oass = ObservableAnalysisSerializer(
            data={}, context={"request": MockRequest(self.user)}
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

        oass = ObservableAnalysisSerializer(
            data={}, context={"request": MockRequest(self.user)}
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

    def test_filter_connectors_all(self):

        oass = ObservableAnalysisSerializer(
            data={}, context={"request": MockRequest(self.user)}
        )
        connectors = _AbstractJobCreateSerializer.filter_connectors(
            oass, {"tlp": "WHITE", "connectors_requested": []}
        )
        total = 0
        for connector in ConnectorConfig.objects.all():
            if connector.is_runnable(self.user):
                total += 1
        self.assertEqual(len(connectors), total)

    def test_filter_connectors_is_runnable(self):
        c = ConnectorConfig.objects.get(name="MISP")
        c.maximum_tlp = "WHITE"

        self.assertFalse(c.is_runnable(self.user))
        oass = ObservableAnalysisSerializer(
            data={}, context={"request": MockRequest(self.user)}
        )
        connectors = _AbstractJobCreateSerializer.filter_connectors(
            oass, {"tlp": "WHITE", "connectors_requested": [c]}
        )
        self.assertEqual(0, len(connectors))
        with patch.object(c, "is_runnable") as is_runnable:
            is_runnable.return_value = True
            connectors = _AbstractJobCreateSerializer.filter_connectors(
                oass, {"tlp": "WHITE", "connectors_requested": [c]}
            )
            self.assertCountEqual(connectors, [c])

    def test_filter_connectors_tlp(self):
        c = ConnectorConfig.objects.get(name="MISP")
        c.maximum_tlp = "WHITE"
        oass = ObservableAnalysisSerializer(
            data={}, context={"request": MockRequest(self.user)}
        )
        with patch.object(c, "is_runnable") as is_runnable:
            is_runnable.return_value = True
            connectors = _AbstractJobCreateSerializer.filter_connectors(
                oass, {"tlp": "GREEN", "connectors_requested": [c]}
            )
            self.assertEqual(0, len(connectors))
            connectors = _AbstractJobCreateSerializer.filter_connectors(
                oass, {"tlp": "WHITE", "connectors_requested": [c]}
            )
            self.assertCountEqual(connectors, [c])

    def test_filter_visualizers_all(self):
        v = VisualizerConfig.objects.get(name="Yara")
        v.analyzers.set(AnalyzerConfig.objects.none())
        v.connectors.set(AnalyzerConfig.objects.none())
        oass = ObservableAnalysisSerializer(
            data={}, context={"request": MockRequest(self.user)}
        )
        with patch.object(VisualizerConfig.objects, "all") as all:
            all.return_value = [v]
            visualizers = _AbstractJobCreateSerializer.filter_visualizers(
                oass, {"analyzers_to_execute": [], "connectors_to_execute": []}
            )
            self.assertCountEqual(visualizers, [v])

    def test_filter_visualizers_is_runnable(self):
        v = VisualizerConfig.objects.get(name="Yara")
        v.analyzers.set(AnalyzerConfig.objects.none())
        v.connectors.set(AnalyzerConfig.objects.none())
        self.assertTrue(v.is_runnable(self.user))
        oass = ObservableAnalysisSerializer(
            data={}, context={"request": MockRequest(self.user)}
        )
        with patch.object(VisualizerConfig.objects, "all") as all:
            all.return_value = [v]
            visualizers = _AbstractJobCreateSerializer.filter_visualizers(
                oass, {"analyzers_to_execute": [], "connectors_to_execute": []}
            )
            self.assertCountEqual(visualizers, [v])
            with patch.object(v, "is_runnable") as is_runnable:
                is_runnable.return_value = False
                visualizers = _AbstractJobCreateSerializer.filter_visualizers(
                    oass, {"analyzers_to_execute": [], "connectors_to_execute": []}
                )
                self.assertCountEqual(visualizers, [])

    def test_filter_visualizers_analyzer_subset(self):
        v = VisualizerConfig.objects.get(name="Yara")
        v.analyzers.set(AnalyzerConfig.objects.none())
        v.connectors.set(AnalyzerConfig.objects.none())
        oass = ObservableAnalysisSerializer(
            data={}, context={"request": MockRequest(self.user)}
        )
        with patch.object(VisualizerConfig.objects, "all") as all:
            all.return_value = VisualizerConfig.objects.filter(name="Yara")
            # equal
            visualizers = _AbstractJobCreateSerializer.filter_visualizers(
                oass, {"analyzers_to_execute": [], "connectors_to_execute": []}
            )
            self.assertCountEqual(visualizers, [v])

            # bigger
            visualizers = _AbstractJobCreateSerializer.filter_visualizers(
                oass,
                {
                    "analyzers_to_execute": [AnalyzerConfig.objects.first()],
                    "connectors_to_execute": [],
                },
            )
            self.assertCountEqual(visualizers, [v])

            # smaller
            v.analyzers.set(AnalyzerConfig.objects.all())
            visualizers = _AbstractJobCreateSerializer.filter_visualizers(
                oass, {"analyzers_to_execute": [], "connectors_to_execute": []}
            )
            self.assertCountEqual(visualizers, [])

    def test_filter_visualizers_connector_subset(self):
        v = VisualizerConfig.objects.get(name="Yara")
        v.analyzers.set(AnalyzerConfig.objects.none())
        v.connectors.set(AnalyzerConfig.objects.none())
        oass = ObservableAnalysisSerializer(
            data={}, context={"request": MockRequest(self.user)}
        )
        with patch.object(VisualizerConfig.objects, "all") as all:
            all.return_value = VisualizerConfig.objects.filter(name="Yara")
            # equal
            visualizers = _AbstractJobCreateSerializer.filter_visualizers(
                oass, {"analyzers_to_execute": [], "connectors_to_execute": []}
            )
            self.assertCountEqual(visualizers, [v])

            # bigger
            visualizers = _AbstractJobCreateSerializer.filter_visualizers(
                oass,
                {
                    "analyzers_to_execute": [],
                    "connectors_to_execute": [ConnectorConfig.objects.first()],
                },
            )
            self.assertCountEqual(visualizers, [v])

            # smaller
            v.connectors.set(ConnectorConfig.objects.all())
            visualizers = _AbstractJobCreateSerializer.filter_visualizers(
                oass, {"analyzers_to_execute": [], "connectors_to_execute": []}
            )
            self.assertCountEqual(visualizers, [])
