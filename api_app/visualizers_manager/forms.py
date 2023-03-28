from django import forms
from django.forms import ModelForm

from api_app.visualizers_manager.classes import Visualizer


class VisualizerConfigAdminForm(ModelForm):
    python_module = forms.ChoiceField(
        required=True,
        widget=forms.Select,
        choices=[
            (class_.__name__, class_.python_module)
            for class_ in Visualizer.all_subclasses()
        ],
    )
