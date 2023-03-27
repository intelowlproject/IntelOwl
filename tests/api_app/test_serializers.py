# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from django.conf import settings
from django.core.files import File
from django.http.request import MultiValueDict, QueryDict
from rest_framework.exceptions import ValidationError

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.serializers import (
    FileAnalysisSerializer,
    ObservableAnalysisSerializer,
    _AbstractJobCreateSerializer,
)
from api_app.visualizers_manager.models import VisualizerConfig
from tests import CustomTestCase
from tests.mock_utils import MockRequest


# class PlaybookObservableAnalysisSerializerTestCase(CustomTestCase):
#     PLAYBOOK = "FREE_TO_USE_ANALYZERS"
#
#     IP = "1.1.1.1"
#
#     def test_save(self):
#
#         data = {
#             "observables": [["ip", self.IP]],
#             "playbooks_requested": [self.PLAYBOOK],
#         }
#         playbook = PlaybookConfig.objects.filter(pk=self.PLAYBOOK).first()
#         self.assertIsNotNone(playbook)
#         serializer = PlaybookObservableAnalysisSerializer(
#             data=data, many=True, context={"request": MockRequest(self.user)}
#         )
#         try:
#             serializer.is_valid(raise_exception=True)
#         except ValidationError as e:
#             self.fail(e)
#
#         jobs = serializer.save()
#         self.assertEqual(1, len(jobs))
#         job = jobs[0]
#         self.assertEqual(list(job.playbooks_to_execute.all()), [playbook])
#
#
# class PlaybookFileAnalysisSerializerTestCase(CustomTestCase):
#     FILE = "file.exe"
#     PLAYBOOK = "FREE_TO_USE_ANALYZERS"
#
#     def _read_file_save_job(self, filename: str):
#         test_file = f"{settings.PROJECT_LOCATION}/test_files/{filename}"
#         self.f = open(test_file, "rb")
#         return File(self.f)
#
#     def test_save(self):
#         playbook = PlaybookConfig.objects.filter(pk=self.PLAYBOOK).first()
#         self.assertIsNotNone(playbook)
#
#         file = self._read_file_save_job(filename=self.FILE)
#
#         data = {
#             "files": [file],
#             "file_names": [self.FILE],
#             "playbooks_requested": [self.PLAYBOOK],
#         }
#         qdict = QueryDict("", mutable=True)
#         qdict.update(MultiValueDict(data))
#
#         serializer = PlaybookFileAnalysisSerializer(
#             data=qdict, many=True, context={"request": MockRequest(self.user)}
#         )
#         serializer.is_valid(raise_exception=True)
#         jobs = serializer.save()
#         self.assertEqual(1, len(jobs))
#         job = jobs[0]
#         self.assertEqual(list(job.playbooks_to_execute.all()), [playbook])


class AbstractJobCreateSerializerTestCase(CustomTestCase):
    def setUp(self) -> None:
        self.ajcs = _AbstractJobCreateSerializer(
            data={}, context={"request": MockRequest(self.user)}
        )
        self.ajcs.all_analyzers = False
        self.ajcs.all_connectors = False

    def test_validate_analyzers_requested(self):
        analyzers = _AbstractJobCreateSerializer.filter_analyzers_requested(
            self.ajcs, []
        )
        self.assertEqual(len(analyzers), AnalyzerConfig.objects.all().count())
        self.assertTrue(self.ajcs.all_analyzers)

    def test_filter_analyzers_not_runnable(self):
        a = AnalyzerConfig.objects.get(name="Tranco")
        a.disabled = True
        with self.assertRaises(ValidationError):
            _AbstractJobCreateSerializer.set_analyzers_to_execute(
                self.ajcs, [a], {"tlp": "WHITE", "analyzers_requested": [a]}
            )
        a.disabled = False
        analyzers = _AbstractJobCreateSerializer.set_analyzers_to_execute(
            self.ajcs, [a], {"tlp": "WHITE", "analyzers_requested": [a]}
        )
        self.assertCountEqual(analyzers, [a])

    def test_filter_analyzers_maximum_tlp(self):
        a = AnalyzerConfig.objects.get(name="Tranco")
        a.maximum_tlp = "WHITE"
        self.ajcs.all_analyzers = False
        with self.assertRaises(ValidationError):
            _AbstractJobCreateSerializer.set_analyzers_to_execute(
                self.ajcs, [a], {"tlp": "GREEN", "analyzers_requested": [a]}
            )

        a.maximum_tlp = "GREEN"
        analyzers = _AbstractJobCreateSerializer.set_analyzers_to_execute(
            self.ajcs, [a], {"tlp": "GREEN", "analyzers_requested": [a]}
        )
        self.assertCountEqual(analyzers, [a])

    def test_filter_connectors_all(self):

        connectors = _AbstractJobCreateSerializer.set_connectors_to_execute(
            self.ajcs, [], {"tlp": "WHITE", "connectors_requested": []}
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
        connectors = _AbstractJobCreateSerializer.set_connectors_to_execute(
            self.ajcs, [c], {"tlp": "WHITE", "connectors_requested": [c]}
        )
        self.assertEqual(0, len(connectors))
        with patch.object(c, "is_runnable") as is_runnable:
            is_runnable.return_value = True
            connectors = _AbstractJobCreateSerializer.set_connectors_to_execute(
                self.ajcs, [c], {"tlp": "WHITE", "connectors_requested": [c]}
            )
            self.assertCountEqual(connectors, [c])

    def test_filter_connectors_tlp(self):
        c = ConnectorConfig.objects.get(name="MISP")
        c.maximum_tlp = "WHITE"
        with patch.object(c, "is_runnable") as is_runnable:
            is_runnable.return_value = True
            connectors = _AbstractJobCreateSerializer.set_connectors_to_execute(
                self.ajcs, [c], {"tlp": "GREEN", "connectors_requested": [c]}
            )
            self.assertEqual(0, len(connectors))
            connectors = _AbstractJobCreateSerializer.set_connectors_to_execute(
                self.ajcs, [c], {"tlp": "WHITE", "connectors_requested": [c]}
            )
            self.assertCountEqual(connectors, [c])

    def test_filter_visualizers_all(self):
        v = VisualizerConfig.objects.get(name="Yara")
        v.analyzers.set(AnalyzerConfig.objects.none())
        v.connectors.set(AnalyzerConfig.objects.none())
        with patch.object(VisualizerConfig.objects, "all") as all:
            all.return_value = [v]
            visualizers = _AbstractJobCreateSerializer.set_visualizers_to_execute(
                self.ajcs, [], []
            )
            self.assertCountEqual(visualizers, [v])

    def test_filter_visualizers_is_runnable(self):
        v = VisualizerConfig.objects.get(name="Yara")
        v.analyzers.set(AnalyzerConfig.objects.none())
        v.connectors.set(AnalyzerConfig.objects.none())
        self.assertTrue(v.is_runnable(self.user))
        with patch.object(VisualizerConfig.objects, "all") as all:
            all.return_value = [v]
            visualizers = _AbstractJobCreateSerializer.set_visualizers_to_execute(
                self.ajcs, [], []
            )
            self.assertCountEqual(visualizers, [v])
            with patch.object(v, "is_runnable") as is_runnable:
                is_runnable.return_value = False
                visualizers = _AbstractJobCreateSerializer.set_visualizers_to_execute(
                    self.ajcs, [], []
                )
                self.assertCountEqual(visualizers, [])

    def test_filter_visualizers_analyzer_subset(self):
        v = VisualizerConfig.objects.get(name="Yara")
        v.analyzers.set(AnalyzerConfig.objects.none())
        v.connectors.set(AnalyzerConfig.objects.none())
        with patch.object(VisualizerConfig.objects, "all") as all:
            all.return_value = VisualizerConfig.objects.filter(name="Yara")
            # equal
            visualizers = _AbstractJobCreateSerializer.set_visualizers_to_execute(
                self.ajcs, [], []
            )
            self.assertCountEqual(visualizers, [v])

            # bigger
            visualizers = _AbstractJobCreateSerializer.set_visualizers_to_execute(
                self.ajcs, [AnalyzerConfig.objects.first()], []
            )
            self.assertCountEqual(visualizers, [v])

            # smaller
            v.analyzers.set(AnalyzerConfig.objects.all())
            visualizers = _AbstractJobCreateSerializer.set_visualizers_to_execute(
                self.ajcs, [], []
            )
            self.assertCountEqual(visualizers, [])

    def test_filter_visualizers_connector_subset(self):
        v = VisualizerConfig.objects.get(name="Yara")
        v.analyzers.set(AnalyzerConfig.objects.none())
        v.connectors.set(AnalyzerConfig.objects.none())
        with patch.object(VisualizerConfig.objects, "all") as all:
            all.return_value = VisualizerConfig.objects.filter(name="Yara")
            # equal
            visualizers = _AbstractJobCreateSerializer.set_visualizers_to_execute(
                self.ajcs, [], []
            )
            self.assertCountEqual(visualizers, [v])

            # bigger
            visualizers = _AbstractJobCreateSerializer.set_visualizers_to_execute(
                self.ajcs,
                [],
                [ConnectorConfig.objects.first()],
            )
            self.assertCountEqual(visualizers, [v])

            # smaller
            v.connectors.set(ConnectorConfig.objects.all())
            visualizers = _AbstractJobCreateSerializer.set_visualizers_to_execute(
                self.ajcs, [], []
            )
            self.assertCountEqual(visualizers, [])


class FileJobCreateSerializerTestCase(CustomTestCase):
    def setUp(self) -> None:
        self.fas = FileAnalysisSerializer(
            data={}, context={"request": MockRequest(self.user)}
        )
        self.fas.all_analyzers = False
        self.fas.all_connectors = False

    def test_filter_analyzers_type(self):
        a = AnalyzerConfig.objects.get(name="Tranco")
        a.type = "observable"
        a.save()

        with self.assertRaises(ValidationError):
            FileAnalysisSerializer.set_analyzers_to_execute(
                self.fas,
                [a],
                {
                    "tlp": "WHITE",
                    "file_mimetype": "text/html",
                    "analyzers_requested": [a],
                },
            )
        a.type = "file"
        a.save()
        self.assertTrue(
            AnalyzerConfig.objects.filter(
                name="Tranco", supported_filetypes__len=0
            ).exists()
        )
        analyzers = FileAnalysisSerializer.set_analyzers_to_execute(
            self.fas,
            [a],
            {"tlp": "WHITE", "file_mimetype": "text/html", "analyzers_requested": [a]},
        )
        self.assertCountEqual(analyzers, [a])

    def test_filter_analyzer_mimetype(self):
        a = AnalyzerConfig.objects.get(name="Tranco")
        a.type = "file"
        a.supported_filetypes = ["text/rtf"]
        a.save()

        with self.assertRaises(ValidationError):
            FileAnalysisSerializer.set_analyzers_to_execute(
                self.fas,
                [a],
                {
                    "tlp": "WHITE",
                    "file_mimetype": "text/html",
                    "analyzers_requested": [a],
                },
            )

        analyzers = FileAnalysisSerializer.set_analyzers_to_execute(
            self.fas,
            [a],
            {"tlp": "WHITE", "file_mimetype": "text/rtf", "analyzers_requested": [a]},
        )
        self.assertCountEqual(analyzers, [a])

        a.supported_filetypes = []
        a.not_supported_filetypes = ["text/html"]
        a.save()

        with self.assertRaises(ValidationError):
            FileAnalysisSerializer.set_analyzers_to_execute(
                self.fas,
                [a],
                {
                    "tlp": "WHITE",
                    "file_mimetype": "text/html",
                    "analyzers_requested": [a],
                },
            )

        analyzers = FileAnalysisSerializer.set_analyzers_to_execute(
            self.fas,
            [a],
            {"tlp": "WHITE", "file_mimetype": "text/rtf", "analyzers_requested": [a]},
        )
        self.assertCountEqual(analyzers, [a])


class ObservableJobCreateSerializerTestCase(CustomTestCase):
    def setUp(self) -> None:
        self.oass = ObservableAnalysisSerializer(
            data={}, context={"request": MockRequest(self.user)}
        )
        self.oass.all_analyzers = False
        self.oass.all_connectors = False

    def test_filter_analyzers_type(self):
        a = AnalyzerConfig.objects.get(name="Tranco")
        a.observable_supported = ["domain"]
        a.type = "file"
        a.save()
        with self.assertRaises(ValidationError):
            ObservableAnalysisSerializer.set_analyzers_to_execute(
                self.oass,
                [a],
                {
                    "tlp": "WHITE",
                    "analyzers_requested": [a],
                    "observable_classification": "domain",
                },
            )
        a.type = "observable"
        a.save()
        analyzers = ObservableAnalysisSerializer.set_analyzers_to_execute(
            self.oass,
            [a],
            {
                "tlp": "WHITE",
                "analyzers_requested": [a],
                "observable_classification": "domain",
            },
        )
        self.assertCountEqual(analyzers, [a])

    def test_filter_analyzer_observable_supported(self):
        a = AnalyzerConfig.objects.get(name="Tranco")
        a.observable_supported = ["ip"]
        a.type = "observable"
        a.save()
        with self.assertRaises(ValidationError):
            ObservableAnalysisSerializer.set_analyzers_to_execute(
                self.oass,
                [a],
                {
                    "tlp": "WHITE",
                    "analyzers_requested": [a],
                    "observable_classification": "domain",
                },
            )
        a.observable_supported = ["domain"]
        a.save()
        analyzers = ObservableAnalysisSerializer.set_analyzers_to_execute(
            self.oass,
            [a],
            {
                "tlp": "WHITE",
                "analyzers_requested": [a],
                "observable_classification": "domain",
            },
        )
        self.assertCountEqual(analyzers, [a])
