from django import forms
from django.forms import ModelForm

from api_app.analyzers_manager.classes import FileAnalyzer, ObservableAnalyzer


class AnalyzerConfigAdminForm(ModelForm):
    python_module = forms.ChoiceField(
        required=True,
        widget=forms.Select,
        choices=[
            (class_.__name__, class_.python_module)
            for class_ in ObservableAnalyzer.all_subclasses()
            + FileAnalyzer.all_subclasses()
        ],
    )
