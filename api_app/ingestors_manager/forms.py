from django import forms
from django.forms import ModelForm

from api_app.ingestors_manager.classes import Ingestor


class IngestorConfigAdminForm(ModelForm):
    python_module = forms.ChoiceField(
        required=True,
        widget=forms.Select,
        choices=[
            (class_.python_module, class_.__name__)
            for class_ in sorted(
                Ingestor.all_subclasses(),
                key=lambda x: x.__name__,
            )
        ],
    )
