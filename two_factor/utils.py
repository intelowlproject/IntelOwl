from urllib.parse import quote, urlencode

from django.conf import settings
from django_otp import devices_for_user

USER_DEFAULT_DEVICE_ATTR_NAME = "_default_device"


def default_device(user):
    if not user or user.is_anonymous:
        return
    if hasattr(user, USER_DEFAULT_DEVICE_ATTR_NAME):
        return getattr(user, USER_DEFAULT_DEVICE_ATTR_NAME)
    for device in devices_for_user(user):
        if device.name == "default":
            setattr(user, USER_DEFAULT_DEVICE_ATTR_NAME, device)
            return device


def get_otpauth_url(accountname, secret, issuer=None, digits=None):
    # For a complete run-through of all the parameters, have a look at the
    # specs at:
    # https://github.com/google/google-authenticator/wiki/Key-Uri-Format

    # quote and urlencode work best with bytes, not unicode strings.
    accountname = accountname.encode("utf8")
    issuer = issuer.encode("utf8") if issuer else None

    label = quote(b": ".join([issuer, accountname]) if issuer else accountname)

    # Ensure that the secret parameter is the FIRST parameter of the URI, this
    # allows Microsoft Authenticator to work.
    query = [("secret", secret), ("digits", digits or totp_digits())]

    if issuer:
        query.append(("issuer", issuer))

    return "otpauth://totp/%s?%s" % (label, urlencode(query))


# from http://mail.python.org/pipermail/python-dev/2008-January/076194.html
def monkeypatch_method(cls):
    def decorator(func):
        setattr(cls, func.__name__, func)
        return func

    return decorator


def totp_digits():
    """
    Returns the number of digits (as configured by the TWO_FACTOR_TOTP_DIGITS setting)
    for totp tokens. Defaults to 6
    """
    return getattr(settings, "TWO_FACTOR_TOTP_DIGITS", 6)
