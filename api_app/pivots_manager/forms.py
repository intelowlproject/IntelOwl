from django import forms

from api_app.pivots_manager.models import PivotConfig


class PivotConfigAdminForm(forms.ModelForm):
    description = forms.CharField(
        disabled=True,
        required=False,
        initial="<generated automatically>",
        widget=forms.Textarea(),
    )

    class Meta:
        model = PivotConfig
        fields = [
            "name",
            "description",
            "config",
            "disabled",
            "disabled_in_organizations",
            "python_module",
            "field_to_compare",
            "related_analyzer_config",
            "related_connector_config",
            "playbook_to_execute",
        ]
