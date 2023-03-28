from django import forms
from django.forms import ModelForm

from api_app.connectors_manager.classes import Connector


class ConnectorConfigAdminForm(ModelForm):
    python_module = forms.ChoiceField(
        required=True,
        widget=forms.Select,
        choices=[
            (class_.__name__, class_.python_module)
            for class_ in Connector.all_subclasses()
        ],
    )
