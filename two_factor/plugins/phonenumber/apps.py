from django.apps import AppConfig
from django.conf import settings
from django.test.signals import setting_changed

from two_factor.plugins.registry import registry


class TwoFactorPhoneNumberConfig(AppConfig):
    name = "two_factor.plugins.phonenumber"
    verbose_name = "Django Two Factor Authentication – Phone Method"
    default_auto_field = "django.db.models.AutoField"
    url_prefix = "phone"

    def ready(self):
        register_methods(self, None, None)
        setting_changed.connect(register_methods)


def register_methods(sender, setting, value, **kwargs):
    # This allows for dynamic registration, typically when testing.
    from .method import PhoneCallMethod, SMSMethod

    if getattr(settings, "TWO_FACTOR_CALL_GATEWAY", None):
        registry.register(PhoneCallMethod())
    else:
        registry.unregister("call")
    if getattr(settings, "TWO_FACTOR_SMS_GATEWAY", None):
        registry.register(SMSMethod())
    else:
        registry.unregister("sms")
