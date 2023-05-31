# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import datetime
import os

from django.conf import settings
from django.utils.timezone import now

from api_app.analyzers_manager.constants import ObservableTypes
from api_app.analyzers_manager.file_analyzers import quark_engine, yara_scan
from api_app.analyzers_manager.observable_analyzers import (
    maxmind,
    phishing_army,
    talos,
    tor,
)
from api_app.models import Job
from intel_owl.tasks import check_stuck_analysis, remove_old_jobs

from . import CustomTestCase, get_logger
from .mock_utils import MockUpResponse, if_mock_connections, patch, skip

logger = get_logger()


class CronTests(CustomTestCase):
    def test_check_stuck_analysis(self):
        _job = Job.objects.create(
            user=self.user,
            status=Job.Status.RUNNING.value,
            observable_name="8.8.8.8",
            observable_classification=ObservableTypes.IP,
            received_request_time=now(),
        )
        self.assertCountEqual(check_stuck_analysis(), [])

        _job.received_request_time = now() - datetime.timedelta(hours=1)
        _job.save()
        self.assertCountEqual(check_stuck_analysis(), [_job.pk])

        _job.status = Job.Status.PENDING.value
        _job.save()
        self.assertCountEqual(check_stuck_analysis(check_pending=False), [])

        self.assertCountEqual(check_stuck_analysis(check_pending=True), [_job.pk])
        _job.delete()

    def test_remove_old_jobs(self):
        _job = Job.objects.create(
            user=self.user,
            status=Job.Status.FAILED.value,
            observable_name="8.8.8.8",
            observable_classification=ObservableTypes.IP,
            received_request_time=now(),
            finished_analysis_time=now(),
        )
        self.assertEqual(remove_old_jobs(), 0)

        _job.finished_analysis_time = now() - datetime.timedelta(days=10)
        _job.save()
        self.assertEqual(remove_old_jobs(), 1)

        _job.delete()

    @if_mock_connections(skip("not working without connection"))
    def test_maxmind_updater(self):
        maxmind.Maxmind._update()
        for db in maxmind.db_names:
            self.assertTrue(os.path.exists(db))

    @if_mock_connections(
        patch(
            "requests.get", return_value=MockUpResponse({}, 200, text="91.192.100.61")
        )
    )
    def test_talos_updater(self, mock_get=None):
        db_file_path = talos.Talos._update()
        self.assertTrue(os.path.exists(db_file_path))

    @if_mock_connections(
        patch(
            "requests.get", return_value=MockUpResponse({}, 200, text="91.192.100.61")
        )
    )
    def test_phishing_army_updater(self, mock_get=None):
        db_file_path = phishing_army.PhishingArmy._update()
        self.assertTrue(os.path.exists(db_file_path))

    @if_mock_connections(
        patch(
            "requests.get", return_value=MockUpResponse({}, 200, text="93.95.230.253")
        )
    )
    def test_tor_updater(self, mock_get=None):
        db_file_path = tor.Tor._update()
        self.assertTrue(os.path.exists(db_file_path))

    def test_quark_updater(self):
        from quark.config import DIR_PATH

        quark_engine.QuarkEngine._update()
        self.assertTrue(os.path.exists(DIR_PATH))

    def test_yara_updater(self):
        yara_scan.YaraScan._update()
        self.assertTrue(len(os.listdir(settings.YARA_RULES_PATH)))
