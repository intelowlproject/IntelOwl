from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.models import Job
from api_app.pivots_manager.models import Pivot, PivotConfig
from api_app.pivots_manager.serializers import PivotConfigSerializer, PivotSerializer
from api_app.playbooks_manager.models import PlaybookConfig
from tests import CustomTestCase
from tests.mock_utils import MockUpRequest


class PivotSerializerTestCase(CustomTestCase):
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
            field="test.0",
            analyzer_config=AnalyzerConfig.objects.first(),
            playbook_to_execute=PlaybookConfig.objects.first(),
        )

    def tearDown(self) -> None:
        super().tearDown()
        self.j1.delete()
        self.j2.delete()
        self.pc.delete()

    def test_read(self):
        pivot = Pivot.objects.create(
            starting_job=self.j1, ending_job=self.j2, pivot_config=self.pc
        )
        ps = PivotSerializer(pivot)
        self.assertEqual(ps.data["starting_job"], self.j1.pk)
        self.assertEqual(ps.data["ending_job"], self.j2.pk)
        self.assertEqual(ps.data["pivot_config"], self.pc.pk)

        pivot.delete()

    def test_write(self):
        ps = PivotSerializer(
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
            field="test.0",
            analyzer_config=ac,
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        pcs = PivotConfigSerializer(pc)
        result = pcs.data
        self.assertEqual(result["config"], ac.pk)

    def test_write(self):
        ac = AnalyzerConfig.objects.first()
        playbook = PlaybookConfig.objects.first()
        data = {
            "analyzer_config": ac.pk,
            "playbook_to_execute": playbook.pk,
            "field": "test.0",
        }
        pcs = PivotConfigSerializer(data=data)
        pcs.is_valid(raise_exception=True)
        pivot_config = pcs.save()
        self.assertEqual(pivot_config.name, f"{ac.pk}.test.0.{playbook.pk}")
        pivot_config.delete()
