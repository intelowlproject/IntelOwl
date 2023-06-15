from django import forms

from api_app.pivots_manager.models import PivotConfig


class PivotConfigModelForm(forms.ModelForm):

    name = forms.CharField(
        disabled=True, required=False, initial="<generated automatically>"
    )
    description = forms.CharField(
        disabled=True, required=False, initial="<generated automatically>"
    )

    class Meta:
        model = PivotConfig
        fields = [
            "name",
            "description",
            "analyzer_config",
            "connector_config",
            "visualizer_config",
            "field",
            "playbook_to_execute",
        ]
