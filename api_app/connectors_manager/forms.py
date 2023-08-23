from django import forms

from api_app.choices import PythonModuleBasePaths
from api_app.forms import PythonConfigAdminForm
from api_app.models import PythonModule


class ConnectorConfigAdminForm(PythonConfigAdminForm):
    python_module = forms.ChoiceField(
        required=True,
        widget=forms.Select,
        choices=[
            (python_module, python_module.module)
            for python_module in PythonModule.objects.filter(
                base_path=PythonModuleBasePaths.Connector.value
            )
        ],
    )
