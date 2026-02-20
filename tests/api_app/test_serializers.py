# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import datetime

from django.contrib.auth import get_user_model
from django.utils.timezone import now
from rest_framework.exceptions import ValidationError

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer
from api_app.choices import Classification, PythonModuleBasePaths
from api_app.connectors_manager.models import ConnectorConfig
from api_app.models import Job, Parameter, PluginConfig, PythonModule
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.serializers.job import (
    CommentSerializer,
    FileJobSerializer,
    JobRecentScanSerializer,
    JobResponseSerializer,
    ObservableAnalysisSerializer,
    RestJobSerializer,
    _AbstractJobCreateSerializer,
)
from api_app.serializers.plugin import (
    PluginConfigSerializer,
    PythonConfigListSerializer,
)
from api_app.visualizers_manager.models import VisualizerConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization
from tests import CustomTestCase
from tests.mock_utils import MockUpRequest

User = get_user_model()


class JobRecentScanSerializerTestCase(CustomTestCase):
    def test_to_representation(self):
        an = Analyzable.objects.create(name="gigatest.com", classification="domain")
        j1 = Job.objects.create(
            **{
                "user": self.user,
                "finished_analysis_time": now() - datetime.timedelta(hours=2),
                "analyzable": an,
            }
        )
        data = JobRecentScanSerializer(j1).data
        self.assertIn("pk", data)
        self.assertIn("playbook", data)
        self.assertIn("user", data)
        self.assertIn("importance", data)
        self.assertIn("tlp", data)


class PluginConfigSerializerTestCase(CustomTestCase):
    def test_to_representation(self):
        org = Organization.objects.create(name="test_org")

        m1 = Membership.objects.create(user=self.user, organization=org, is_owner=True)
        param = Parameter.objects.filter(
            python_module__base_path=PythonModuleBasePaths.FileAnalyzer.value,
            type="str",
        ).first()
        pc = PluginConfig.objects.create(
            value="https://intelowl.com",
            owner=self.user,
            parameter=param,
            analyzer_config=AnalyzerConfig.objects.filter(python_module=param.python_module).first(),
            for_organization=True,
        )
        data = PluginConfigSerializer(pc, context={"request": MockUpRequest(user=self.user)}).data
        self.assertEqual(org.name, data["organization"])
        pc.delete()
        pc = PluginConfig.objects.create(
            value="https://intelowl.com",
            owner=self.user,
            parameter=param,
            analyzer_config=AnalyzerConfig.objects.filter(python_module=param.python_module).first(),
            for_organization=False,
        )
        data = PluginConfigSerializer(pc, context={"request": MockUpRequest(user=self.user)}).data
        self.assertIsNone(data["organization"])
        m1.delete()
        org.delete()
        pc.delete()

    def test_create(self):
        org = Organization.objects.create(name="test_org")
        m1 = Membership.objects.create(user=self.user, organization=org, is_owner=True)
        ac = AnalyzerConfig.objects.get(name="AbuseIPDB")
        param = Parameter.objects.create(
            is_secret=True,
            name="mynewparameter",
            python_module=ac.python_module,
            required=True,
            type="str",
        )

        payload = {
            "attribute": param.name,
            "value": "new_value",
            "organization": "test_org",
            "parameter": param.pk,
            "analyzer_config": ac.name,
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

    def test_validate(self):
        org = Organization.objects.create(name="test_org")
        m1 = Membership.objects.create(user=self.superuser, organization=org, is_owner=True)
        m2 = Membership.objects.create(user=self.admin, organization=org, is_owner=False, is_admin=True)
        m3 = Membership.objects.create(user=self.user, organization=org, is_owner=False, is_admin=False)
        ac = AnalyzerConfig.objects.get(name="AbuseIPDB")
        param = Parameter.objects.create(
            is_secret=True,
            name="mynewparameter",
            python_module=ac.python_module,
            required=True,
            type="str",
        )

        payload = {
            "attribute": param.name,
            "value": "new value",
            "organization": "test_org",
            "parameter": param.pk,
            "analyzer_config": ac.name,
        }
        serializer = PluginConfigSerializer(
            data=payload,
            context={"request": MockUpRequest(user=self.superuser)},
        )
        serializer.is_valid(raise_exception=True)
        pc: PluginConfig = serializer.save()
        self.assertTrue(pc.for_organization)
        pc.delete()

        serializer = PluginConfigSerializer(
            data=payload,
            context={"request": MockUpRequest(user=self.admin)},
        )
        serializer.is_valid(raise_exception=True)
        pc: PluginConfig = serializer.save()
        self.assertTrue(pc.for_organization)
        pc.delete()

        serializer = PluginConfigSerializer(
            data=payload,
            context={"request": MockUpRequest(user=self.user)},
        )
        with self.assertRaises(ValidationError):
            serializer.is_valid(raise_exception=True)
        self.assertTrue(pc.for_organization)

        serializer = PluginConfigSerializer(
            data=payload,
            context={"request": MockUpRequest(user=self.guest)},
        )
        with self.assertRaises(ValidationError):
            serializer.is_valid(raise_exception=True)
        self.assertTrue(pc.for_organization)

        m1.delete()
        m2.delete()
        m3.delete()
        org.delete()


class RestJobSerializerTestCase(CustomTestCase):
    def test_validate(self):
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        job = Job.objects.create(
            analyzable=an,
            user=self.user,
        )
        js = RestJobSerializer(job)
        self.assertIn("analyzer_reports", js.data)
        self.assertIn("connector_reports", js.data)
        self.assertIn("visualizer_reports", js.data)
        job.delete()
        an.delete()


class AbstractJobCreateSerializerTestCase(CustomTestCase):
    def setUp(self) -> None:
        self.ajcs = _AbstractJobCreateSerializer(data={}, context={"request": MockUpRequest(self.user)})
        self.ajcs.Meta.model = Job

    def test_check_previous_job(self):
        Job.objects.all().delete()
        a1 = AnalyzerConfig.objects.order_by("?").first()
        a2 = AnalyzerConfig.objects.order_by("?").exclude(pk=a1.pk).first()
        a3 = AnalyzerConfig.objects.order_by("?").exclude(pk__in=[a1.pk, a2.pk]).first()
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        j1 = Job.objects.create(
            analyzable=an,
            user=self.user,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
            received_request_time=now() - datetime.timedelta(hours=3),
        )
        j1.analyzers_requested.add(a1)
        j1.analyzers_requested.add(a2)

        self.ajcs = _AbstractJobCreateSerializer(data={}, context={"request": MockUpRequest(self.user)})
        self.assertEqual(
            j1,
            self.ajcs.check_previous_jobs(
                validated_data={
                    "scan_check_time": datetime.timedelta(days=1),
                    "analyzable": an,
                    "analyzers_to_execute": [],
                }
            ),
        )
        self.assertEqual(
            j1,
            self.ajcs.check_previous_jobs(
                validated_data={
                    "scan_check_time": datetime.timedelta(days=1),
                    "analyzable": an,
                    "analyzers_to_execute": [a1],
                }
            ),
        )
        self.assertEqual(
            j1,
            self.ajcs.check_previous_jobs(
                validated_data={
                    "scan_check_time": datetime.timedelta(days=1),
                    "analyzable": an,
                    "analyzers_to_execute": [a1, a2],
                }
            ),
        )
        with self.assertRaises(Job.DoesNotExist):
            self.ajcs.check_previous_jobs(
                validated_data={
                    "scan_check_time": datetime.timedelta(days=1),
                    "analyzable": an,
                    "analyzers_to_execute": [a1, a2, a3],
                }
            )
        j1.delete()
        an.delete()

    def test_set_default_value_from_playbook(self):
        data = {"playbook_requested": PlaybookConfig.objects.first()}
        self.ajcs.set_default_value_from_playbook(data)
        self.assertIn("scan_mode", data)
        self.assertIn("scan_check_time", data)
        self.assertIn("tlp", data)

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

    def test_filter_analyzers_not_runnable(self):
        a = AnalyzerConfig.objects.get(name="Tranco")
        a.disabled = True
        a.save()
        self.assertCountEqual(self.ajcs.set_analyzers_to_execute([a], "CLEAR"), [])
        a.disabled = False
        a.save()
        analyzers = self.ajcs.set_analyzers_to_execute([a], "CLEAR")
        self.assertCountEqual(analyzers, [a])

    def test_filter_analyzers_maximum_tlp(self):
        a = AnalyzerConfig.objects.get(name="Tranco")
        previous_tlp = a.maximum_tlp
        a.maximum_tlp = "CLEAR"
        a.save()
        self.assertCountEqual(self.ajcs.set_analyzers_to_execute([a], "GREEN"), [])

        a.maximum_tlp = "GREEN"
        a.save()
        analyzers = self.ajcs.set_analyzers_to_execute([a], "GREEN")
        a.maximum_tlp = previous_tlp
        a.save()
        self.assertCountEqual(analyzers, [a])

    def test_filter_connectors_is_runnable(self):
        cc = ConnectorConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Connector.value, module="misp.MISP"
            ),
            description="test",
            disabled=True,
            maximum_tlp="CLEAR",
        )
        pc = PluginConfig.objects.create(
            parameter=Parameter.objects.get(name="api_key_name", python_module=cc.python_module),
            connector_config=cc,
            value="test",
            owner=None,
            for_organization=False,
        )
        pc2 = PluginConfig.objects.create(
            parameter=Parameter.objects.get(name="url_key_name", python_module=cc.python_module),
            connector_config=cc,
            value="test.com",
            owner=None,
            for_organization=False,
        )

        self.assertFalse(cc.is_runnable(self.user))
        connectors = _AbstractJobCreateSerializer.set_connectors_to_execute(self.ajcs, [cc], "CLEAR")
        self.assertEqual(0, len(connectors))
        cc.disabled = False
        cc.save()
        connectors = _AbstractJobCreateSerializer.set_connectors_to_execute(self.ajcs, [cc], "CLEAR")
        self.assertCountEqual(connectors, [cc])
        pc.delete()
        pc2.delete()
        cc.delete()

    def test_filter_connectors_tlp(self):
        cc = ConnectorConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Connector.value, module="misp.MISP"
            ),
            description="test",
            disabled=False,
            maximum_tlp="CLEAR",
        )
        pc = PluginConfig.objects.create(
            parameter=Parameter.objects.get(name="api_key_name", python_module=cc.python_module),
            connector_config=cc,
            value="test",
            owner=None,
            for_organization=False,
        )
        pc2 = PluginConfig.objects.create(
            parameter=Parameter.objects.get(name="url_key_name", python_module=cc.python_module),
            connector_config=cc,
            value="test.com",
            owner=None,
            for_organization=False,
        )
        connectors = _AbstractJobCreateSerializer.set_connectors_to_execute(self.ajcs, [cc], "GREEN")
        self.assertEqual(0, len(connectors))
        connectors = _AbstractJobCreateSerializer.set_connectors_to_execute(self.ajcs, [cc], "CLEAR")
        self.assertCountEqual(connectors, [cc])
        cc.delete()
        pc.delete()
        pc2.delete()

    def test_filter_visualizers_all(self):
        v = VisualizerConfig.objects.get(name="Yara")
        pc = PlaybookConfig.objects.create(name="test", description="test", type=["ip"])
        v.playbooks.set([pc])
        visualizers = _AbstractJobCreateSerializer.set_visualizers_to_execute(
            self.ajcs, tlp="CLEAR", playbook_requested=pc
        )
        self.assertCountEqual(visualizers, [v])
        pc.delete()

    def test_filter_visualizers_is_runnable(self):
        v = VisualizerConfig.objects.get(name="Yara")
        pc = PlaybookConfig.objects.create(name="test", description="test", type=["ip"])
        v.playbooks.set([pc])
        v.save()
        self.assertTrue(v.is_runnable(self.user))
        visualizers = _AbstractJobCreateSerializer.set_visualizers_to_execute(
            self.ajcs, tlp="CLEAR", playbook_requested=pc
        )
        self.assertCountEqual(visualizers, [v])
        v.disabled = True
        v.save()
        visualizers = _AbstractJobCreateSerializer.set_visualizers_to_execute(
            self.ajcs, tlp="CLEAR", playbook_requested=pc
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
        self.fas = FileJobSerializer(data={}, context={"request": MockUpRequest(self.user)})

    def test_filter_analyzers_type(self):
        a = AnalyzerConfig.objects.get(name="Tranco")
        a.type = "observable"
        a.save()

        self.assertCountEqual(
            [],
            FileJobSerializer.set_analyzers_to_execute(
                self.fas, [a], tlp="CLEAR", file_mimetype="text/html", file_name=""
            ),
        )

        a.type = "file"
        a.save()
        self.assertTrue(AnalyzerConfig.objects.filter(name="Tranco", supported_filetypes__len=0).exists())
        analyzers = FileJobSerializer.set_analyzers_to_execute(
            self.fas, [a], tlp="CLEAR", file_mimetype="text/html", file_name=""
        )
        self.assertCountEqual(analyzers, [a])

    def test_filter_analyzer_mimetype(self):
        a = AnalyzerConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.FileAnalyzer.value,
                module="yara_scan.YaraScan",
            ),
            description="test",
            disabled=False,
            supported_filetypes=["text/rtf"],
            type="file",
            run_hash=False,
        )

        self.assertCountEqual(
            [],
            FileJobSerializer.set_analyzers_to_execute(
                self.fas, [a], tlp="CLEAR", file_mimetype="text/html", file_name=""
            ),
        )

        analyzers = FileJobSerializer.set_analyzers_to_execute(
            self.fas, [a], tlp="CLEAR", file_mimetype="text/rtf", file_name=""
        )
        self.assertCountEqual(analyzers, [a])

        a.supported_filetypes = []
        a.not_supported_filetypes = ["text/html"]
        a.save()

        self.assertCountEqual(
            [],
            FileJobSerializer.set_analyzers_to_execute(
                self.fas, [a], tlp="CLEAR", file_mimetype="text/html", file_name=""
            ),
        )

        analyzers = FileJobSerializer.set_analyzers_to_execute(
            self.fas, [a], tlp="CLEAR", file_mimetype="text/rtf", file_name=""
        )
        self.assertCountEqual(analyzers, [a])
        a.delete()


class ObservableJobCreateSerializerTestCase(CustomTestCase):
    def setUp(self) -> None:
        self.oass = ObservableAnalysisSerializer(data={}, context={"request": MockUpRequest(self.user)})

    def test_filter_analyzers_type(self):
        a = AnalyzerConfig.objects.get(name="Yara")
        a.observable_supported = ["domain"]
        a.type = "file"
        a.save()
        self.assertCountEqual(
            [],
            ObservableAnalysisSerializer.set_analyzers_to_execute(
                self.oass, [a], tlp="CLEAR", observable_classification="domain"
            ),
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
        self.assertCountEqual(
            [],
            ObservableAnalysisSerializer.set_analyzers_to_execute(
                self.oass, [a], tlp="CLEAR", observable_classification="domain"
            ),
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
        self.an = Analyzable.objects.create(name="test.com", classification=Classification.DOMAIN)
        self.job = Job.objects.create(
            analyzable=self.an,
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
        self.an.delete()

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
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )
        job = Job.objects.create(
            analyzable=an,
        )
        result = JobResponseSerializer(job).data
        self.assertIn("status", result)
        self.assertEqual(result["status"], "accepted")
        self.assertIn("job_id", result)
        self.assertEqual(result["job_id"], job.id)
        job.delete()
        an.delete()

    def test_many(self):
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )
        an2 = Analyzable.objects.create(
            name="test2.com",
            classification=Classification.DOMAIN,
        )

        job1 = Job.objects.create(
            analyzable=an,
        )
        job2 = Job.objects.create(
            analyzable=an2,
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
        an.delete()
        an2.delete()


class AbstractListConfigSerializerTestCase(CustomTestCase):
    def test_to_representation(self):
        # this analyzer has 0 missing secrets
        ac = AnalyzerConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.FileAnalyzer.value, module="apkid.APKiD"
            ),
            description="test",
            disabled=False,
            maximum_tlp="CLEAR",
        )
        acs = PythonConfigListSerializer(
            context={"request": MockUpRequest(self.user)},
            child=AnalyzerConfigSerializer(),
        )
        result = list(acs.to_representation([ac]))
        self.assertEqual(1, len(result))
        result = result[0]
        self.assertIn("verification", result)
        self.assertIn("missing_secrets", result["verification"])
        self.assertFalse(
            result["verification"]["missing_secrets"],
            result["verification"]["missing_secrets"],
        )
        self.assertIn("configured", result["verification"])
        self.assertTrue(result["verification"]["configured"])
        ac.delete()

        ac = AnalyzerConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.FileAnalyzer.value, module="apkid.APKiD"
            ),
            description="test",
            disabled=False,
            maximum_tlp="CLEAR",
        )
        param: Parameter = Parameter.objects.create(
            python_module=ac.python_module,
            name="test",
            type="str",
            required=True,
            is_secret=True,
        )
        acs = PythonConfigListSerializer(
            context={"request": MockUpRequest(self.user)},
            child=AnalyzerConfigSerializer(),
        )
        result = list(acs.to_representation([ac]))
        self.assertEqual(1, len(result))
        result = result[0]

        self.assertIn("verification", result)
        self.assertIn("configured", result["verification"])
        self.assertFalse(result["verification"]["configured"])
        self.assertIn("missing_secrets", result["verification"])
        self.assertEqual(1, len(result["verification"]["missing_secrets"]))
        self.assertEqual("test", result["verification"]["missing_secrets"][0])
        param.delete()
        ac.delete()
