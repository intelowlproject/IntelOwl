from django import forms

from api_app.models import Parameter, PluginConfig


class ParameterInlineForm(forms.ModelForm):
    default = forms.JSONField(required=False)

    class Meta:
        model = Parameter
        fields = ("name", "type", "description", "is_secret", "required")

    def __init__(self, *args, **kwargs):
        instance: Parameter = kwargs.get("instance")
        if instance:
            try:
                pc = PluginConfig.objects.get(parameter=instance, owner__isnull=True)
            except PluginConfig.DoesNotExist:
                default = None
            else:
                default = pc.value
            kwargs["initial"] = {"default": default}
        super().__init__(*args, **kwargs)

    def save(self, commit: bool = ...):
        instance = super().save(commit=commit)
        if self.cleaned_data["default"] is not None:
            pc = PluginConfig(
                value=self.cleaned_data["default"],
                owner=None,
                for_organization=False,
                parameter=instance,
            )
            pc.full_clean()
            pc.save()

        return instance
