from django.contrib import admin

from .models import PhoneDevice


class PhoneDeviceAdmin(admin.ModelAdmin):
    """
    :class:`~django.contrib.admin.ModelAdmin` for
    :class:`~two_factor.plugins.phonenumber.models.PhoneDevice`.
    """

    raw_id_fields = ("user",)


admin.site.register(PhoneDevice, PhoneDeviceAdmin)
