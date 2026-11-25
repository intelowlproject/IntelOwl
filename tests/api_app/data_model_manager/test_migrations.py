from django.db import connection
from django.db.migrations.executor import MigrationExecutor

from api_app.helpers import calculate_md5, calculate_sha1, calculate_sha256
from tests import CustomTestCase


class MigrationIntegrityTestCase(CustomTestCase):
    @property
    def app_name(self):
        return "data_model_manager"

    @property
    def migration_from(self):
        return "0012_domaindatamodel_fingerprint_and_more"

    @property
    def migration_to(self):
        return "0013_populate_fingerprints"

    def setUp(self):
        super().setUp()
        self.executor = MigrationExecutor(connection)
        self.old_state = self.executor.migrate([(self.app_name, self.migration_from)])

    def test_migration_0013_deduplication_integrity(self):
        old_apps = self.old_state.apps
        IPDataModel = old_apps.get_model(self.app_name, "IPDataModel")
        UserAnalyzableEvent = old_apps.get_model("user_events_manager", "UserAnalyzableEvent")
        Analyzable = old_apps.get_model("analyzables_manager", "Analyzable")
        ContentType = old_apps.get_model("contenttypes", "ContentType")
        User = old_apps.get_model("certego_saas_user", "User")
        user = User.objects.create(username="test_migrator", email="test@intelowl.org")
        name1, name2 = "1.1.1.1", "8.8.8.8"
        az1 = Analyzable.objects.create(
            name=name1,
            classification="ip",
            md5=calculate_md5(name1.encode()),
            sha1=calculate_sha1(name1.encode()),
            sha256=calculate_sha256(name1.encode()),
        )
        az2 = Analyzable.objects.create(
            name=name2,
            classification="ip",
            md5=calculate_md5(name2.encode()),
            sha1=calculate_sha1(name2.encode()),
            sha256=calculate_sha256(name2.encode()),
        )
        dm1 = IPDataModel.objects.create(evaluation="benign", reliability=5)
        dm2 = IPDataModel.objects.create(evaluation="benign", reliability=5)
        ct = ContentType.objects.get_for_model(IPDataModel)
        UserAnalyzableEvent.objects.create(
            user=user, analyzable=az1, data_model_content_type=ct, data_model_object_id=dm1.id
        )
        UserAnalyzableEvent.objects.create(
            user=user, analyzable=az2, data_model_content_type=ct, data_model_object_id=dm2.id
        )
        self.executor.loader.build_graph()
        new_state = self.executor.migrate([(self.app_name, self.migration_to)])
        new_apps = new_state.apps
        IPDataModelNew = new_apps.get_model(self.app_name, "IPDataModel")
        UserAnalyzableEventNew = new_apps.get_model("user_events_manager", "UserAnalyzableEvent")
        self.assertEqual(IPDataModelNew.objects.count(), 1)
        canonical = IPDataModelNew.objects.first()
        events = UserAnalyzableEventNew.objects.filter(data_model_object_id=canonical.id)
        self.assertEqual(events.count(), 2)
        self.assertFalse(IPDataModelNew.objects.filter(id=dm2.id).exists())

    def tearDown(self):
        self.executor.migrate(self.executor.loader.graph.leaf_nodes())
        super().tearDown()
