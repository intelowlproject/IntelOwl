


from django.test import TestCase

from api_app.analyzers_manager.file_analyzers.yara_scan import YaraScan
from api_app.models import PluginConfig, PythonModule


class TestYaraAnalyzer(TestCase):
    def setUp(self):
        self.pm = PythonModule.objects.get(
            module="yara_scan.YaraScan",
            base_path="api_app.analyzers_manager.file_analyzers"
        )
        self.param = self.pm.parameters.get(name="repositories")
        self.pc = PluginConfig.objects.filter(parameter=self.param).first()
        self.ys = YaraScan(config=self.pc)

    def test_update_runs(self):
        self.ys.update()

    def test_unprotect_url_in_config(self):
        self.assertIn(
            "https://yaraify.abuse.ch/yarahub/yaraify-rules.zip",
            self.pc.value
)

