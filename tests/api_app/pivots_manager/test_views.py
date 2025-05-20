from typing import Type

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import Classification
from api_app.models import Job, PythonModule
from api_app.pivots_manager.models import PivotConfig, PivotMap
from api_app.playbooks_manager.models import PlaybookConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization
from tests import CustomViewSetTestCase, ViewSetTestCaseMixin
from tests.api_app.test_views import AbstractConfigViewSetTestCaseMixin


class PivotMapViewSetTestCase(ViewSetTestCaseMixin, CustomViewSetTestCase):
    URL = "/api/pivot_map"

    @classmethod
    @property
    def model_class(cls) -> Type[PivotMap]:
        return PivotMap

    def get_object(self):
        return self.model_class.objects.order_by("?").first().pk

    def test_get(self):
        self.client.force_authenticate(self.superuser)

        plugin = self.model_class.objects.order_by("?").first().pk
        response = self.client.get(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 403, response.json())

        self.client.force_authenticate(None)
        response = self.client.get(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 401, response.json())

        self.client.force_authenticate(self.user)
        response = self.client.get(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 200, response.json())

    def setUp(self):
        super().setUp()
        self.an1 = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )
        self.an2 = Analyzable.objects.create(
            name="test2.com",
            classification=Classification.DOMAIN,
        )

        self.j1 = Job.objects.create(
            user=self.user,
            analyzable=self.an1,
            status="reported_without_fails",
        )
        self.j2 = Job.objects.create(
            user=self.user,
            analyzable=self.an2,
            status="reported_without_fails",
        )
        self.pc = PivotConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
        )
        self.pc.playbooks_choice.add(PlaybookConfig.objects.first())
        self.pivot = PivotMap.objects.create(
            starting_job=self.j1, ending_job=self.j2, pivot_config=self.pc
        )

    def tearDown(self) -> None:
        super().tearDown()
        self.j1.delete()
        self.j2.delete()
        self.an1.delete()
        self.an2.delete()
        self.pc.delete()
        PivotMap.objects.all().delete()

    def test_get_superuser(self):
        plugin = self.get_object()
        self.client.force_authenticate(self.superuser)
        response = self.client.get(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 403, response.json())


class PivotConfigViewSetTestCase(
    AbstractConfigViewSetTestCaseMixin, CustomViewSetTestCase
):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    URL = "/api/pivot"

    def setUp(self):
        super().setUp()
        self.pc = PivotConfig(
            name="test",
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
        )
        self.pc.save()
        self.pc.playbooks_choice.add(PlaybookConfig.objects.first())

    def tearDown(self) -> None:
        super().tearDown()
        self.pc.delete()

    @classmethod
    @property
    def model_class(cls) -> Type[PivotConfig]:
        return PivotConfig

    def test_create(self):
        # invalid fields
        response = self.client.post(
            self.URL,
            data={
                "name": "TestCreate",
                "python_module": "self_analyzable.SelfAnalyzable",
                "playbooks_choice": [PlaybookConfig.objects.first().name],
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400)

        # no plugin config
        response = self.client.post(
            self.URL,
            data={
                "name": "TestCreate",
                "related_analyzer_configs": [AnalyzerConfig.objects.first().name],
                "python_module": "self_analyzable.SelfAnalyzable",
                "playbooks_choice": [PlaybookConfig.objects.first().name],
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.json())
        try:
            pc = PivotConfig.objects.get(name="TestCreate")
        except PivotConfig.DoesNotExist as e:
            self.fail(e)
        else:
            pc.delete()

    def test_update(self):
        org1, _ = Organization.objects.get_or_create(name="test")
        m_user, _ = Membership.objects.get_or_create(
            user=self.user, organization=org1, is_owner=False
        )

        # user not in org can't update pivot
        self.client.force_authenticate(self.guest)
        plugin = self.model_class.objects.order_by("?").first().name
        response = self.client.patch(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 403, response.json())
        # superuser not in org can update pivot
        self.client.force_authenticate(self.superuser)
        response = self.client.patch(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 200, response.json())
        # user in org can't update pivot
        self.client.force_authenticate(m_user.user)
        plugin = self.model_class.objects.order_by("?").first().name
        response = self.client.patch(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 403, response.json())
        # owner/admin can update pivot
        m_user.is_owner = True
        m_user.is_admin = True
        m_user.save()
        self.client.force_authenticate(m_user.user)
        response = self.client.patch(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 200, response.json())

    def test_delete(self):
        org1, _ = Organization.objects.get_or_create(name="test")
        m_user, _ = Membership.objects.get_or_create(
            user=self.user, organization=org1, is_owner=False
        )
        pc1 = PivotConfig(
            name="test1",
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
        )
        pc1.save()
        pc1.playbooks_choice.add(PlaybookConfig.objects.first())

        # user not in org can't delete pivot
        self.client.force_authenticate(self.guest)
        response = self.client.delete(f"{self.URL}/{self.pc.name}")
        self.assertEqual(response.status_code, 403, response.json())
        # superuser not in org can update pivot
        self.client.force_authenticate(self.superuser)
        response = self.client.delete(f"{self.URL}/{self.pc.name}")
        self.assertEqual(response.status_code, 204)
        # user in org can't delete pivot
        self.client.force_authenticate(m_user.user)
        response = self.client.delete(f"{self.URL}/{pc1.name}")
        self.assertEqual(response.status_code, 403, response.json())
        # owner/admin can delete pivot
        m_user.is_owner = True
        m_user.is_admin = True
        m_user.save()
        self.client.force_authenticate(m_user.user)
        response = self.client.delete(f"{self.URL}/{pc1.name}")
        self.assertEqual(response.status_code, 204)
