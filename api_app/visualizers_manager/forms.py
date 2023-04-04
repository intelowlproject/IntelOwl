from django import forms
from django.forms import ModelForm

from api_app.visualizers_manager.classes import Visualizer


class VisualizerConfigAdminForm(ModelForm):
    python_module = forms.ChoiceField(
        required=True,
        widget=forms.Select,
        choices=[
            (class_.python_module, class_.__name__)
            for class_ in Visualizer.all_subclasses()
        ],
    )
