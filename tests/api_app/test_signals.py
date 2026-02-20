from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer
from api_app.choices import PythonModuleBasePaths
from api_app.models import Parameter, PythonModule
from api_app.serializers.plugin import PythonConfigListSerializer
from tests import CustomTestCase


class PreDeleteParameterTestCase(CustomTestCase):
    def test_cache(self):
        pm = PythonModule.objects.filter(base_path=PythonModuleBasePaths.ObservableAnalyzer.value).first()
        ac: AnalyzerConfig = AnalyzerConfig.objects.filter(python_module=pm).first()

        new_param = Parameter.objects.create(
            python_module=pm,
            name="test",
            type="str",
            description="test",
            is_secret=False,
            required=False,
        )
        data = PythonConfigListSerializer(child=AnalyzerConfigSerializer()).to_representation_single_plugin(
            ac, self.user
        )
        self.assertIn("test", dict(data)["params"])
        new_param.delete()
        data = PythonConfigListSerializer(child=AnalyzerConfigSerializer()).to_representation_single_plugin(
            ac, self.user
        )
        self.assertNotIn("test", dict(data)["params"])
