# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import os

from django.test import TestCase

from api_app import crons
from api_app.analyzers_manager.file_analyzers import quark_engine, yara_scan
from api_app.analyzers_manager.observable_analyzers import maxmind, talos, tor

from . import get_logger
from .mock_utils import MockResponse, if_mock_connections, patch, skip

logger = get_logger()


class CronTests(TestCase):
    def test_check_stuck_analysis(self):
        jobs_id_stuck = crons.check_stuck_analysis()
        logger.info(f"jobs_id_stuck: {jobs_id_stuck}")
        self.assertTrue(True)

    def test_remove_old_jobs(self):
        num_jobs_to_delete = crons.remove_old_jobs()
        logger.info(f"old jobs deleted: {num_jobs_to_delete}")
        self.assertTrue(True)

    @if_mock_connections(skip("not working without connection"))
    def test_maxmind_updater(self):
        for db in maxmind.db_names:
            db_file_path = maxmind.Maxmind.updater({}, db)
            self.assertTrue(os.path.exists(db_file_path))

    @if_mock_connections(
        patch("requests.get", return_value=MockResponse({}, 200, text="91.192.100.61"))
    )
    def test_talos_updater(self, mock_get=None):
        db_file_path = talos.Talos.updater()
        self.assertTrue(os.path.exists(db_file_path))

    @if_mock_connections(
        patch("requests.get", return_value=MockResponse({}, 200, text="93.95.230.253"))
    )
    def test_tor_updater(self, mock_get=None):
        db_file_path = tor.Tor.updater()
        self.assertTrue(os.path.exists(db_file_path))

    def test_quark_updater(self):
        quark_engine.QuarkEngine.updater()
        self.assertTrue(os.path.exists(quark_engine.QuarkEngine.QUARK_RULES_PATH))

    def test_yara_updater(self):
        file_paths = yara_scan.YaraScan.update_rules()
        for file_path in file_paths:
            print(file_path)
            self.assertTrue(os.path.exists(file_path))
