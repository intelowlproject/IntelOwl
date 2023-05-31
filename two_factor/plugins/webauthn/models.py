from django.conf import settings
from django.db import models
from django_otp.models import Device, ThrottlingMixin


class WebauthnDevice(ThrottlingMixin, Device):
    """
    Model for Webauthn authentication
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name="webauthn_keys", on_delete=models.CASCADE
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True)

    public_key = models.TextField()
    key_handle = models.TextField()
    sign_count = models.IntegerField()

    def get_throttle_factor(self):
        return settings.TWO_FACTOR_WEBAUTHN_THROTTLE_FACTOR
