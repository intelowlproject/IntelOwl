import django

if django.VERSION <= (3, 2):
    default_app_config = "two_factor.plugins.yubikey.apps.TwoFactorYubikeyConfig"
