import logging
import os

from django.test import TestCase

from api_app.script_analyzers.file_analyzers import yara_scan
from api_app.script_analyzers.observable_analyzers import maxmind,  \
    talos, tor

from api_app import crons
from api_app.utilities import get_analyzer_config

logger = logging.getLogger(__name__)


class CronTests(TestCase):

    def test_check_stuck_analysis(self):
        jobs_id_stuck = crons.check_stuck_analysis()
        print("jobs_id_stuck: {}".format(jobs_id_stuck))
        self.assertTrue(True)

    def test_remove_old_jobs(self):
        num_jobs_to_delete = crons.remove_old_jobs()
        print("old jobs deleted: {}".format(num_jobs_to_delete))
        self.assertTrue(True)

    def test_maxmind_updater(self):
        db_file_path = maxmind.updater({})
        self.assertTrue(os.path.exists(db_file_path))

    def test_talos_updater(self):
        db_file_path = talos.updater()
        self.assertTrue(os.path.exists(db_file_path))

    def test_tor_updater(self):
        db_file_path = tor.updater()
        self.assertTrue(os.path.exists(db_file_path))

    def test_yara_updater(self):
        file_paths = yara_scan.yara_update_repos()
        for file_path in file_paths:
            self.assertTrue(os.path.exists(file_path))


class ConfigTests(TestCase):

    def test_config(self):
        config = get_analyzer_config()
        self.assertNotEqual(config, {})