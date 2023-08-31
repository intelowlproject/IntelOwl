from api_app.choices import PythonModuleBasePaths
from api_app.forms import PythonConfigAdminForm


class ConnectorConfigAdminForm(PythonConfigAdminForm):
    class Meta:
        base_paths_allowed = [PythonModuleBasePaths.Connector.value]
