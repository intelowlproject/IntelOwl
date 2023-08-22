from django import forms
from django.forms import ModelForm

from api_app.analyzers_manager.classes import FileAnalyzer, ObservableAnalyzer


class AnalyzerConfigAdminForm(ModelForm):
    ...
