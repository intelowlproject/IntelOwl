from django import forms
from django.utils.translation import gettext_lazy as _

from .models import PhoneDevice
from .utils import get_available_phone_methods
from .validators import validate_international_phonenumber


class PhoneNumberMethodForm(forms.ModelForm):
    number = forms.CharField(
        label=_("Phone Number"), validators=[validate_international_phonenumber]
    )
    method = forms.ChoiceField(widget=forms.RadioSelect, label=_("Method"))

    class Meta:
        model = PhoneDevice
        fields = ["number", "method"]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.fields["method"].choices = get_available_phone_methods()


class PhoneNumberForm(forms.ModelForm):
    # Cannot use PhoneNumberField, as it produces a PhoneNumber object,
    # which cannot be serialized.
    number = forms.CharField(
        label=_("Phone Number"), validators=[validate_international_phonenumber]
    )

    class Meta:
        model = PhoneDevice
        fields = ["number"]
