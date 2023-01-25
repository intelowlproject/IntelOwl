# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import hashlib
import os
from unittest import SkipTest

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files import File

from api_app.analyzers_manager.dataclasses import AnalyzerConfig
from api_app.connectors_manager.dataclasses import ConnectorConfig
from api_app.models import Job
from tests import PollingFunction

from .. import CustomTestCase

User = get_user_model()


class _AbstractAnalyzersScriptTestCase(CustomTestCase):
    # constants
    TIMEOUT_SECONDS: int = 60 * 5  # 5 minutes
    SLEEP_SECONDS: int = 5  # 5 seconds
    analyzer_configs = AnalyzerConfig.all()
    connector_configs = ConnectorConfig.all()

    # attrs
    test_job: Job
    analyzer_configs: dict
    runtime_configuration: dict
    analyzers_to_test: list

    @classmethod
    def get_params(cls):
        return {
            "analyzers_requested": [],
            "connectors_requested": [],
            "connectors_to_execute": list(cls.connector_configs.keys()),
        }

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        if cls in [
            _AbstractAnalyzersScriptTestCase,
            _ObservableAnalyzersScriptsTestCase,
            _FileAnalyzersScriptsTestCase,
        ]:
            raise SkipTest(f"{cls.__name__} is an abstract base class.")

    def setUp(self):
        analyzers_to_test = os.environ.get("TEST_ANALYZERS", "").split(",")
        self.analyzers_to_test = (
            analyzers_to_test
            if len(analyzers_to_test) and len(analyzers_to_test[0])
            else []
        )
        return super().setUp()

    def tearDown(self):
        self.test_job.delete()
        return super().tearDown()

    def test_pipeline(self, *args, **kwargs):
        print(f"\n[START] -----{self.__class__.__name__}.test_pipeline----")
        print(
            f"[REPORT] Job:{self.test_job.pk}, status:'{self.test_job.status}',",
            f"analyzers:{self.test_job.analyzers_to_execute}",
            f"connectors: {self.test_job.connectors_to_execute}",
        )
        # execute analyzers
        self.test_job.pipeline(self.runtime_configuration)
        poll_result = PollingFunction(self)
        return poll_result


class _ObservableAnalyzersScriptsTestCase(_AbstractAnalyzersScriptTestCase):
    # define runtime configs
    runtime_configuration = {
        "Triage_Search": {
            "max_tries": 1,
        },
        "VirusTotal_v3_Get_Observable": {
            "max_tries": 1,
            "poll_distance": 1,
        },
        "HaveIBeenPwned": {
            "max_tries": 1,
            "domain": "test@test.com",
        },
    }

    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "is_sample": False,
        }

    def setUp(self):
        super().setUp()
        # init job instance
        params = self.get_params()
        params["md5"] = hashlib.md5(
            params["observable_name"].encode("utf-8")
        ).hexdigest()
        self.test_job = Job(user=self.superuser, **params)

        from api_app.models import PluginConfig

        configs = PluginConfig.objects.filter(
            type=PluginConfig.PluginType.ANALYZER,
            config_type=PluginConfig.ConfigType.SECRET,
            owner=self.superuser,
        )
        print("printing found config for superuser")
        for config in configs:
            print(f"attribute: {config.attribute}, value: {config.value}")

        # overwrite if not set in env var
        if len(self.analyzers_to_test):
            self.test_job.analyzers_to_execute = self.analyzers_to_test
        else:
            self.test_job.analyzers_to_execute = [
                config.name
                for config in self.analyzer_configs.values()
                if config.is_observable_type_supported(
                    params["observable_classification"]
                )
            ]
        # save job
        self.test_job.save()


class _FileAnalyzersScriptsTestCase(_AbstractAnalyzersScriptTestCase):
    # define runtime configs
    runtime_configuration = {
        "VirusTotal_v2_Scan_File": {"wait_for_scan_anyway": True, "max_tries": 1},
        "VirusTotal_v3_Scan_File": {"max_tries": 1, "poll_distance": 1},
        "VirusTotal_v3_Get_File": {"max_tries": 1, "poll_distance": 1},
        "VirusTotal_v3_Get_File_And_Scan": {
            "max_tries": 1,
            "poll_distance": 1,
            "force_active_scan": True,
            "force_active_scan_if_old": False,
        },
        "Cuckoo_Scan": {"max_poll_tries": 1, "max_post_tries": 1},
        "PEframe_Scan": {"max_tries": 1},
        "MWDB_Scan": {
            "upload_file": True,
            "max_tries": 1,
        },
        "Doc_Info_Experimental": {
            "additional_passwords_to_check": ["testpassword"],
            "experimental": True,
        },
    }

    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "is_sample": True,
        }

    def setUp(self):
        super().setUp()
        # get params
        params = self.get_params()
        # save job instance
        self.test_job = Job(**params)
        # overwrite if set in env var
        if len(self.analyzers_to_test):
            self.test_job.analyzers_to_execute = self.analyzers_to_test
        self._read_file_save_job(filename=params["file_name"])

    def _read_file_save_job(self, filename: str):
        test_file = f"{settings.PROJECT_LOCATION}/test_files/{filename}"
        with open(test_file, "rb") as f:
            self.test_job.file = File(f)
            self.test_job.md5 = hashlib.md5(f.read()).hexdigest()
            self.test_job.save()
