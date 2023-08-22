from django import forms
from django.forms import ModelForm

from api_app.ingestors_manager.classes import Ingestor


class IngestorConfigAdminForm(ModelForm):
    ...