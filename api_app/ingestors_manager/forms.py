from api_app.choices import PythonModuleBasePaths
from api_app.forms import PythonConfigAdminForm


class IngestorConfigAdminForm(PythonConfigAdminForm):
    class Meta:
        base_paths_allowed = [PythonModuleBasePaths.Ingestor.value]
