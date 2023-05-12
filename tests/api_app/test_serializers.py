# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from rest_framework.exceptions import ValidationError

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.models import Job
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.serializers import (
    CommentSerializer,
    FileAnalysisSerializer,
    JobResponseSerializer,
    ObservableAnalysisSerializer,
    _AbstractJobCreateSerializer,
)
from api_app.visualizers_manager.models import VisualizerConfig
from tests import CustomTestCase
from tests.mock_utils import MockUpRequest


class AbstractJobCreateSerializerTestCase(CustomTestCase):
    def setUp(self) -> None:
        self.ajcs = _AbstractJobCreateSerializer(
            data={}, context={"request": MockUpRequest(self.user)}
        )
        self.ajcs.all_analyzers = False
        self.ajcs.all_connectors = False

    def test_validate_playbook_and_analyzers(self):
        a = AnalyzerConfig.objects.get(name="Tranco")
        with self.assertRaises(ValidationError):
            self.ajcs.validate(
                {
                    "playbook_requested": [PlaybookConfig.objects.first()],
                    "analyzers_requested": [a],
                    "tlp": "CLEAR",
                }
            )

    def test_validate_playbook_disabled(self):
        p = PlaybookConfig.objects.first()
        p.disabled = True
        p.save()
        with self.assertRaises(ValidationError):
            self.ajcs.validate({"playbook_requested": p, "tlp": "CLEAR"})
        p.disabled = False
        p.save()
        self.ajcs.validate({"playbook_requested": p, "tlp": "CLEAR"})

    def test_validate_analyzers_requested(self):
        analyzers = self.ajcs.filter_analyzers_requested([])
        self.assertEqual(len(analyzers), AnalyzerConfig.objects.all().count())
        self.assertTrue(self.ajcs.all_analyzers)

    def test_filter_analyzers_not_runnable(self):
        a = AnalyzerConfig.objects.get(name="Tranco")
        a.disabled = True
        with self.assertRaises(ValidationError):
            self.ajcs.set_analyzers_to_execute(
                [a], {"tlp": "CLEAR", "analyzers_requested": [a]}
            )
        a.disabled = False
        analyzers = self.ajcs.set_analyzers_to_execute(
            [a], {"tlp": "CLEAR", "analyzers_requested": [a]}
        )
        self.assertCountEqual(analyzers, [a])

    def test_filter_analyzers_maximum_tlp(self):
        a = AnalyzerConfig.objects.get(name="Tranco")
        a.maximum_tlp = "CLEAR"
        self.ajcs.all_analyzers = False
        with self.assertRaises(ValidationError):
            self.ajcs.set_analyzers_to_execute(
                [a], {"tlp": "GREEN", "analyzers_requested": [a]}
            )

        a.maximum_tlp = "GREEN"
        analyzers = self.ajcs.set_analyzers_to_execute(
            [a], {"tlp": "GREEN", "analyzers_requested": [a]}
        )
        self.assertCountEqual(analyzers, [a])

    def test_filter_connectors_all(self):

        connectors = self.ajcs.set_connectors_to_execute(
            [], {"tlp": "CLEAR", "connectors_requested": []}
        )
        total = 0
        for connector in ConnectorConfig.objects.all():
            if connector.is_runnable(self.user):
                total += 1
        self.assertEqual(len(connectors), total)

    def test_filter_connectors_is_runnable(self):
        c = ConnectorConfig.objects.get(name="MISP")
        c.maximum_tlp = "CLEAR"

        self.assertFalse(c.is_runnable(self.user))
        connectors = _AbstractJobCreateSerializer.set_connectors_to_execute(
            self.ajcs, [c], {"tlp": "CLEAR", "connectors_requested": [c]}
        )
        self.assertEqual(0, len(connectors))
        with patch.object(c, "is_runnable") as is_runnable:
            is_runnable.return_value = True
            connectors = _AbstractJobCreateSerializer.set_connectors_to_execute(
                self.ajcs, [c], {"tlp": "CLEAR", "connectors_requested": [c]}
            )
            self.assertCountEqual(connectors, [c])

    def test_filter_connectors_tlp(self):
        c = ConnectorConfig.objects.get(name="MISP")
        c.maximum_tlp = "CLEAR"
        with patch.object(c, "is_runnable") as is_runnable:
            is_runnable.return_value = True
            connectors = _AbstractJobCreateSerializer.set_connectors_to_execute(
                self.ajcs, [c], {"tlp": "GREEN", "connectors_requested": [c]}
            )
            self.assertEqual(0, len(connectors))
            connectors = _AbstractJobCreateSerializer.set_connectors_to_execute(
                self.ajcs, [c], {"tlp": "CLEAR", "connectors_requested": [c]}
            )
            self.assertCountEqual(connectors, [c])

    def test_filter_visualizers_all(self):
        v = VisualizerConfig.objects.get(name="Yara")
        v.analyzers.set(AnalyzerConfig.objects.none())
        v.connectors.set(AnalyzerConfig.objects.none())
        with patch.object(VisualizerConfig.objects, "all") as all_objects:
            all_objects.return_value = [v]
            visualizers = _AbstractJobCreateSerializer.set_visualizers_to_execute(
                self.ajcs, [], []
            )
            self.assertCountEqual(visualizers, [v])

    def test_filter_visualizers_is_runnable(self):
        v = VisualizerConfig.objects.get(name="Yara")
        v.analyzers.set(AnalyzerConfig.objects.none())
        v.connectors.set(AnalyzerConfig.objects.none())
        self.assertTrue(v.is_runnable(self.user))
        with patch.object(VisualizerConfig.objects, "all") as all_objects:
            all_objects.return_value = [v]
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
        with patch.object(VisualizerConfig.objects, "all") as all_objects:
            all_objects.return_value = VisualizerConfig.objects.filter(name="Yara")
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
        with patch.object(VisualizerConfig.objects, "all") as all_objects:
            all_objects.return_value = VisualizerConfig.objects.filter(name="Yara")
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

    def test_runtime_configuration_empty(self):
        self.ajcs.validate_runtime_configuration({})

    def test_runtime_configuration_wrong(self):
        with self.assertRaises(ValidationError):
            self.ajcs.validate_runtime_configuration({"tranco": {"key": "value"}})

    def test_runtime_configuration_valid(self):
        self.ajcs.validate_runtime_configuration(
            {
                "analyzers": {"tranco": {"key": "value"}},
                "connectors": {},
                "visualizers": {},
            }
        )


class FileJobCreateSerializerTestCase(CustomTestCase):
    def setUp(self) -> None:
        self.fas = FileAnalysisSerializer(
            data={}, context={"request": MockUpRequest(self.user)}
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
                    "tlp": "CLEAR",
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
            {"tlp": "CLEAR", "file_mimetype": "text/html", "analyzers_requested": [a]},
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
                    "tlp": "CLEAR",
                    "file_mimetype": "text/html",
                    "analyzers_requested": [a],
                },
            )

        analyzers = FileAnalysisSerializer.set_analyzers_to_execute(
            self.fas,
            [a],
            {"tlp": "CLEAR", "file_mimetype": "text/rtf", "analyzers_requested": [a]},
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
                    "tlp": "CLEAR",
                    "file_mimetype": "text/html",
                    "analyzers_requested": [a],
                },
            )

        analyzers = FileAnalysisSerializer.set_analyzers_to_execute(
            self.fas,
            [a],
            {"tlp": "CLEAR", "file_mimetype": "text/rtf", "analyzers_requested": [a]},
        )
        self.assertCountEqual(analyzers, [a])


class ObservableJobCreateSerializerTestCase(CustomTestCase):
    def setUp(self) -> None:
        self.oass = ObservableAnalysisSerializer(
            data={}, context={"request": MockUpRequest(self.user)}
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
                    "tlp": "CLEAR",
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
                "tlp": "CLEAR",
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
                    "tlp": "CLEAR",
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
                "tlp": "CLEAR",
                "analyzers_requested": [a],
                "observable_classification": "domain",
            },
        )
        self.assertCountEqual(analyzers, [a])


class CommentSerializerTestCase(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.job = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            user=self.user,
        )
        self.job.save()

        self.cs = CommentSerializer(
            data={"content": "test", "job_id": self.job.id},
            context={"request": MockUpRequest(self.user)},
        )

    def tearDown(self) -> None:
        super().tearDown()
        self.job.delete()

    def test_create(self):
        self.assertTrue(self.cs.is_valid())
        comment = self.cs.save()
        self.assertEqual(comment.content, "test")
        comment.delete()

    def test_create_with_invalid_job_id(self):
        self.cs.initial_data["job_id"] = 100000
        self.assertFalse(self.cs.is_valid())


class JobResponseSerializerTestCase(CustomTestCase):
    def test_null(self):
        result = JobResponseSerializer(None).data
        self.assertEqual(result, {"status": "not_available", "job_id": None})

    def test_job(self):
        job = Job.objects.create(
            observable_name="test.com", observable_classification="domain"
        )
        result = JobResponseSerializer(job).data
        self.assertIn("status", result)
        self.assertEqual(result["status"], "accepted")
        self.assertIn("job_id", result)
        self.assertEqual(result["job_id"], job.id)
        job.delete()

    def test_many(self):
        job1 = Job.objects.create(
            observable_name="test.com", observable_classification="domain"
        )
        job2 = Job.objects.create(
            observable_name="test2.com", observable_classification="domain"
        )
        result = JobResponseSerializer([job1, job2], many=True).data
        self.assertIn("count", result)
        self.assertEqual(result["count"], 2)
        self.assertIn("results", result)
        self.assertEqual(len(result["results"]), 2)
        self.assertIn("status", result["results"][0])
        self.assertEqual(result["results"][0]["status"], "accepted")
        self.assertIn("job_id", result["results"][0])
        self.assertEqual(result["results"][0]["job_id"], job1.id)
        job1.delete()
        job2.delete()
