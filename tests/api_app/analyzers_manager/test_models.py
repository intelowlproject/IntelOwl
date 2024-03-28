# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from django.core.exceptions import ValidationError

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import PythonModuleBasePaths
from api_app.models import PythonModule
from tests import CustomTestCase


class AnalyzerConfigTestCase(CustomTestCase):
    def test_clean_run_hash_type(self):
        ac = AnalyzerConfig(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.FileAnalyzer.value,
                module="yara_scan.YaraScan",
            ),
            description="test",
            disabled=False,
            type="file",
            run_hash=True,
        )
        with self.assertRaises(ValidationError) as e:
            ac.clean_run_hash_type()
        self.assertEqual(1, len(e.exception.messages))
        self.assertEqual(
            "run_hash_type must be populated if run_hash is True",
            e.exception.messages[0],
        )
