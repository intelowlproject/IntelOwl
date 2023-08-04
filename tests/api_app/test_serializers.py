# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import datetime

from django.utils.timezone import now
from rest_framework.exceptions import ValidationError

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.connectors_manager.serializers import ConnectorConfigSerializer
from api_app.models import Job, Parameter, PluginConfig
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.serializers import (
    CommentSerializer,
    FileAnalysisSerializer,
    JobResponseSerializer,
    JobSerializer,
    ObservableAnalysisSerializer,
    PluginConfigSerializer,
    PythonListConfigSerializer,
    _AbstractJobCreateSerializer,
)
from api_app.visualizers_manager.models import VisualizerConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization
from tests import CustomTestCase
from tests.mock_utils import MockUpRequest


class PluginConfigSerializerTestCase(CustomTestCase):
    def test_to_representation(self):
        org = Organization.objects.create(name="test_org")

        m1 = Membership.objects.create(user=self.user, organization=org, is_owner=True)
        pc = PluginConfig.objects.create(
            value="https://intelowl.com",
            owner=self.user,
            parameter=Parameter.objects.first(),
            for_organization=True,
        )
        data = PluginConfigSerializer(pc).data
        self.assertEqual(org.name, data["organization"])
        pc.delete()
        pc = PluginConfig.objects.create(
            value="https://intelowl.com",
            owner=self.user,
            parameter=Parameter.objects.first(),
            for_organization=False,
        )
        data = PluginConfigSerializer(pc).data
        self.assertIsNone(data["organization"])
        m1.delete()
        org.delete()
        pc.delete()

    def test_create(self):
        org = Organization.objects.create(name="test_org")

        m1 = Membership.objects.create(user=self.user, organization=org, is_owner=True)

        payload = {
            "create": True,
            "edit": True,
            "type": "1",
            "plugin_name": "DNS0_EU",
            "attribute": "query_type",
            "value": "AA",
            "organization": "test_org",
            "config_type": "1",
        }
        serializer = PluginConfigSerializer(
            data=payload,
            context={"request": MockUpRequest(user=self.user)},
        )
        serializer.is_valid(raise_exception=True)
        pc: PluginConfig = serializer.save()
        self.assertTrue(pc.for_organization)
        m1.delete()
        org.delete()
        pc.delete()


class JobSerializerTestCase(CustomTestCase):
    def test_validate(self):
        job = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            user=self.user,
        )
        js = JobSerializer(job)
        self.assertIn("analyzer_reports", js.data)
        self.assertIn("connector_reports", js.data)
        self.assertIn("visualizer_reports", js.data)
        job.delete()


class AbstractJobCreateSerializerTestCase(CustomTestCase):
    def setUp(self) -> None:
        self.ajcs = _AbstractJobCreateSerializer(
            data={}, context={"request": MockUpRequest(self.user)}
        )
        self.ajcs.Meta.model = Job
        self.ajcs.all_analyzers = False
        self.ajcs.all_connectors = False

    def test_check_previous_job(self):
        Job.objects.all().delete()
        a1 = AnalyzerConfig.objects.order_by("?").first()
        a2 = AnalyzerConfig.objects.order_by("?").exclude(pk=a1.pk).first()
        a3 = AnalyzerConfig.objects.order_by("?").exclude(pk__in=[a1.pk, a2.pk]).first()
        j1 = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            user=self.user,
            md5="72cf478e87b031233091d8c00a38ce00",
            status=Job.Status.REPORTED_WITHOUT_FAILS,
            received_request_time=now() - datetime.timedelta(hours=3),
        )
        j1.analyzers_requested.add(a1)
        j1.analyzers_requested.add(a2)

        self.ajcs = _AbstractJobCreateSerializer(
            data={}, context={"request": MockUpRequest(self.user)}
        )
        self.assertEqual(
            j1,
            self.ajcs.check_previous_jobs(
                validated_data={
                    "scan_check_time": datetime.timedelta(days=1),
                    "md5": "72cf478e87b031233091d8c00a38ce00",
                    "analyzers_to_execute": [],
                }
            ),
        )
        self.assertEqual(
            j1,
            self.ajcs.check_previous_jobs(
                validated_data={
                    "scan_check_time": datetime.timedelta(days=1),
                    "md5": "72cf478e87b031233091d8c00a38ce00",
                    "analyzers_to_execute": [a1],
                }
            ),
        )
        self.assertEqual(
            j1,
            self.ajcs.check_previous_jobs(
                validated_data={
                    "scan_check_time": datetime.timedelta(days=1),
                    "md5": "72cf478e87b031233091d8c00a38ce00",
                    "analyzers_to_execute": [a1, a2],
                }
            ),
        )
        with self.assertRaises(Job.DoesNotExist):
            self.ajcs.check_previous_jobs(
                validated_data={
                    "scan_check_time": datetime.timedelta(days=1),
                    "md5": "72cf478e87b031233091d8c00a38ce00",
                    "analyzers_to_execute": [a1, a2, a3],
                }
            )

    def test_set_default_value_from_playbook(self):
        data = {"playbook_requested": PlaybookConfig.objects.first()}
        self.ajcs.set_default_value_from_playbook(data)
        self.assertIn("scan_mode", data)
        self.assertIn("scan_check_time", data)
        self.assertIn("tlp", data)
        self.assertIn("tags", data)

    def test_validate_playbook_and_analyzers(self):
        a = AnalyzerConfig.objects.get(name="Tranco")
        with self.assertRaises(ValidationError):
            self.ajcs.validate(
                {
                    "playbook_requested": PlaybookConfig.objects.first(),
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
        a.save()
        with self.assertRaises(ValidationError):
            self.ajcs.set_analyzers_to_execute([a], "CLEAR")
        a.disabled = False
        a.save()
        analyzers = self.ajcs.set_analyzers_to_execute([a], "CLEAR")
        self.assertCountEqual(analyzers, [a])

    def test_filter_analyzers_maximum_tlp(self):
        a = AnalyzerConfig.objects.get(name="Tranco")
        previous_tlp = a.maximum_tlp
        a.maximum_tlp = "CLEAR"
        a.save()
        self.ajcs.all_analyzers = False
        with self.assertRaises(ValidationError):
            self.ajcs.set_analyzers_to_execute([a], "GREEN")

        a.maximum_tlp = "GREEN"
        a.save()
        analyzers = self.ajcs.set_analyzers_to_execute([a], "GREEN")
        a.maximum_tlp = previous_tlp
        a.save()
        self.assertCountEqual(analyzers, [a])

    def test_filter_connectors_is_runnable(self):
        cc = ConnectorConfig.objects.create(
            name="test",
            python_module="misp.MISP",
            description="test",
            config={"soft_time_limit": 10, "queue": "default"},
            disabled=True,
            maximum_tlp="CLEAR",
        )

        self.assertFalse(cc.is_runnable(self.user))
        connectors = _AbstractJobCreateSerializer.set_connectors_to_execute(
            self.ajcs, [cc], "CLEAR"
        )
        self.assertEqual(0, len(connectors))
        cc.disabled = False
        cc.save()
        connectors = _AbstractJobCreateSerializer.set_connectors_to_execute(
            self.ajcs, [cc], "CLEAR"
        )
        self.assertCountEqual(connectors, [cc])
        cc.delete()

    def test_filter_connectors_tlp(self):
        cc = ConnectorConfig.objects.create(
            name="test",
            python_module="misp.MISP",
            description="test",
            config={"soft_time_limit": 10, "queue": "default"},
            disabled=False,
            maximum_tlp="CLEAR",
        )
        connectors = _AbstractJobCreateSerializer.set_connectors_to_execute(
            self.ajcs, [cc], "GREEN"
        )
        self.assertEqual(0, len(connectors))
        connectors = _AbstractJobCreateSerializer.set_connectors_to_execute(
            self.ajcs, [cc], "CLEAR"
        )
        self.assertCountEqual(connectors, [cc])
        cc.delete()

    def test_filter_visualizers_all(self):
        v = VisualizerConfig.objects.get(name="Yara")
        pc = PlaybookConfig.objects.create(name="test", description="test", type=["ip"])
        v.playbook = pc
        v.save()
        visualizers = _AbstractJobCreateSerializer.set_visualizers_to_execute(
            self.ajcs, pc
        )
        self.assertCountEqual(visualizers, [v])
        pc.delete()

    def test_filter_visualizers_is_runnable(self):
        v = VisualizerConfig.objects.get(name="Yara")
        pc = PlaybookConfig.objects.create(name="test", description="test", type=["ip"])
        v.playbook = pc
        v.save()
        self.assertTrue(v.is_runnable(self.user))
        visualizers = _AbstractJobCreateSerializer.set_visualizers_to_execute(
            self.ajcs, pc
        )
        self.assertCountEqual(visualizers, [v])
        v.disabled = True
        v.save()
        visualizers = _AbstractJobCreateSerializer.set_visualizers_to_execute(
            self.ajcs, pc
        )
        self.assertCountEqual(visualizers, [])
        v.disabled = False
        v.save()
        pc.delete()

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
                self.fas, [a], tlp="CLEAR", file_mimetype="text/html", file_name=""
            )
        a.type = "file"
        a.save()
        self.assertTrue(
            AnalyzerConfig.objects.filter(
                name="Tranco", supported_filetypes__len=0
            ).exists()
        )
        analyzers = FileAnalysisSerializer.set_analyzers_to_execute(
            self.fas, [a], tlp="CLEAR", file_mimetype="text/html", file_name=""
        )
        self.assertCountEqual(analyzers, [a])

    def test_filter_analyzer_mimetype(self):
        a = AnalyzerConfig.objects.create(
            name="test",
            python_module="yara_scan.YaraScan",
            description="test",
            config={"soft_time_limit": 10, "queue": "default"},
            disabled=False,
            supported_filetypes=["text/rtf"],
            type="file",
            run_hash=False,
        )

        with self.assertRaises(ValidationError):
            FileAnalysisSerializer.set_analyzers_to_execute(
                self.fas, [a], tlp="CLEAR", file_mimetype="text/html", file_name=""
            )

        analyzers = FileAnalysisSerializer.set_analyzers_to_execute(
            self.fas, [a], tlp="CLEAR", file_mimetype="text/rtf", file_name=""
        )
        self.assertCountEqual(analyzers, [a])

        a.supported_filetypes = []
        a.not_supported_filetypes = ["text/html"]
        a.save()

        with self.assertRaises(ValidationError):
            FileAnalysisSerializer.set_analyzers_to_execute(
                self.fas, [a], tlp="CLEAR", file_mimetype="text/html", file_name=""
            )

        analyzers = FileAnalysisSerializer.set_analyzers_to_execute(
            self.fas, [a], tlp="CLEAR", file_mimetype="text/rtf", file_name=""
        )
        self.assertCountEqual(analyzers, [a])
        a.delete()


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
                self.oass, [a], tlp="CLEAR", observable_classification="domain"
            )
        a.type = "observable"
        a.save()
        analyzers = ObservableAnalysisSerializer.set_analyzers_to_execute(
            self.oass, [a], tlp="CLEAR", observable_classification="domain"
        )
        self.assertCountEqual(analyzers, [a])

    def test_filter_analyzer_observable_supported(self):
        a = AnalyzerConfig.objects.get(name="Tranco")
        a.observable_supported = ["ip"]
        a.type = "observable"
        a.save()
        with self.assertRaises(ValidationError):
            ObservableAnalysisSerializer.set_analyzers_to_execute(
                self.oass, [a], tlp="CLEAR", observable_classification="domain"
            )
        a.observable_supported = ["domain"]
        a.save()
        analyzers = ObservableAnalysisSerializer.set_analyzers_to_execute(
            self.oass, [a], tlp="CLEAR", observable_classification="domain"
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


class AbstractListConfigSerializerTestCase(CustomTestCase):
    def test_to_representation(self):
        cc = ConnectorConfig.objects.create(
            name="test",
            python_module="misp.MISP",
            description="test",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            maximum_tlp="CLEAR",
        )
        ccs = PythonListConfigSerializer(
            context={"request": MockUpRequest(self.user)},
            child=ConnectorConfigSerializer(),
        )
        result = list(ccs.to_representation([cc]))
        self.assertEqual(1, len(result))
        result = result[0]
        self.assertIn("verification", result)
        self.assertIn("configured", result["verification"])
        self.assertTrue(result["verification"]["configured"])
        self.assertIn("missing_secrets", result["verification"])
        self.assertFalse(result["verification"]["missing_secrets"])
        cc.delete()

        cc = ConnectorConfig.objects.create(
            name="test",
            python_module="misp.MISP",
            description="test",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            maximum_tlp="CLEAR",
        )
        param: Parameter = Parameter.objects.create(
            connector_config=cc,
            name="test",
            type="str",
            required=True,
            is_secret=True,
        )
        ccs = PythonListConfigSerializer(
            context={"request": MockUpRequest(self.user)},
            child=ConnectorConfigSerializer(),
        )
        result = list(ccs.to_representation([cc]))
        self.assertEqual(1, len(result))
        result = result[0]

        self.assertIn("verification", result)
        self.assertIn("configured", result["verification"])
        self.assertFalse(result["verification"]["configured"])
        self.assertIn("missing_secrets", result["verification"])
        self.assertEqual(1, len(result["verification"]["missing_secrets"]))
        self.assertEqual("test", result["verification"]["missing_secrets"][0])
        param.delete()
        cc.delete()
