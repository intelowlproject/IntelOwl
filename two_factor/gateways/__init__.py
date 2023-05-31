from django.conf import settings
from django.utils.module_loading import import_string


def get_gateway_class(import_path):
    return import_string(import_path)


def make_call(device, token):
    gateway = get_gateway_class(getattr(settings, "TWO_FACTOR_CALL_GATEWAY"))()
    gateway.make_call(device=device, token=token)


def send_sms(device, token):
    gateway = get_gateway_class(getattr(settings, "TWO_FACTOR_SMS_GATEWAY"))()
    gateway.send_sms(device=device, token=token)
