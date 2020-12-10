import logging
import os

from django.test import TestCase
from unittest import skipIf

from api_app.script_analyzers.file_analyzers import yara_scan
from api_app.script_analyzers.observable_analyzers import maxmind, talos, tor

from api_app import crons
from api_app.helpers import get_analyzer_config
from intel_owl import settings

logger = logging.getLogger(__name__)
# disable logging library for Continuous Integration
if settings.DISABLE_LOGGING_TEST:
    logging.disable(logging.CRITICAL)


class CronTests(TestCase):
    def test_check_stuck_analysis(self):
        jobs_id_stuck = crons.check_stuck_analysis()
        logger.info(f"jobs_id_stuck: {jobs_id_stuck}")
        self.assertTrue(True)

    def test_remove_old_jobs(self):
        num_jobs_to_delete = crons.remove_old_jobs()
        logger.info(f"old jobs deleted: {num_jobs_to_delete}")
        self.assertTrue(True)

    @skipIf(settings.MOCK_CONNECTIONS, "not working without connection")
    def test_maxmind_updater(self):
        db_file_path = maxmind.Maxmind.updater({})
        self.assertTrue(os.path.exists(db_file_path))

    def test_talos_updater(self):
        db_file_path = talos.Talos.updater()
        self.assertTrue(os.path.exists(db_file_path))

    def test_tor_updater(self):
        db_file_path = tor.Tor.updater()
        self.assertTrue(os.path.exists(db_file_path))

    def test_yara_updater(self):
        file_paths = yara_scan.YaraScan.yara_update_repos()
        for file_path in file_paths:
            self.assertTrue(os.path.exists(file_path))


class ConfigTests(TestCase):
    def test_config(self):
        config = get_analyzer_config()
        self.assertNotEqual(config, {})
