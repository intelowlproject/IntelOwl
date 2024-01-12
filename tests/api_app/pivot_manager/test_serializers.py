from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.models import Job, PythonModule
from api_app.pivots_manager.models import PivotConfig, PivotMap
from api_app.pivots_manager.serializers import PivotConfigSerializer, PivotMapSerializer
from api_app.playbooks_manager.models import PlaybookConfig
from tests import CustomTestCase
from tests.mock_utils import MockUpRequest


class PivotMapSerializerTestCase(CustomTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.j1 = Job.objects.create(
            user=self.user,
            observable_name="test.com",
            observable_classification="domain",
            status="reported_without_fails",
        )
        self.j2 = Job.objects.create(
            user=self.user,
            observable_name="test2.com",
            observable_classification="domain",
            status="reported_without_fails",
        )
        self.pc = PivotConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            playbook_to_execute=PlaybookConfig.objects.first(),
        )

    def tearDown(self) -> None:
        super().tearDown()
        self.j1.delete()
        self.j2.delete()
        self.pc.delete()

    def test_read(self):
        pivot = PivotMap.objects.create(
            starting_job=self.j1, ending_job=self.j2, pivot_config=self.pc
        )
        ps = PivotMapSerializer(pivot)
        self.assertEqual(ps.data["starting_job"], self.j1.pk)
        self.assertEqual(ps.data["ending_job"], self.j2.pk)
        self.assertEqual(ps.data["pivot_config"], self.pc.pk)

        pivot.delete()

    def test_write(self):
        ps = PivotMapSerializer(
            data={
                "starting_job": self.j1.pk,
                "pivot_config": self.pc.pk,
                "ending_job": self.j2.pk,
            },
            context={"request": MockUpRequest(user=self.user)},
        )
        ps.is_valid(raise_exception=True)
        pivot = ps.save()
        pivot.delete()


class PivotConfigSerializerTestCase(CustomTestCase):
    def setUp(self) -> None:
        super().setUp()

    def tearDown(self) -> None:
        super().tearDown()

    def test_read(self):
        ac = AnalyzerConfig.objects.first()
        pc = PivotConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        pc.related_analyzer_configs.set([ac])
        pcs = PivotConfigSerializer(pc)
        result = pcs.data
        self.assertCountEqual(result["related_configs"], [ac.name])
