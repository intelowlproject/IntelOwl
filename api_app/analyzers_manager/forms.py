from api_app.choices import PythonModuleBasePaths
from api_app.forms import PythonConfigAdminForm


class AnalyzerConfigAdminForm(PythonConfigAdminForm):
    class Meta:
        base_paths_allowed = [
            PythonModuleBasePaths.ObservableAnalyzer.value,
            PythonModuleBasePaths.FileAnalyzer.value,
        ]
