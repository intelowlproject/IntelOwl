from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django_otp import devices_for_user


class Command(BaseCommand):
    """
    Command for disabling two-factor authentication for certain users.

    The command accepts any number of usernames, and will remove all OTP
    devices for those users.

    Example usage::

        manage.py two_factor_disable bouke steve
    """

    help = "Disables two-factor authentication for the given users"

    def add_arguments(self, parser):
        parser.add_argument("args", metavar="usernames", nargs="*")

    def handle(self, *usernames, **options):
        User = get_user_model()
        for username in usernames:
            try:
                user = User.objects.get_by_natural_key(username)
            except User.DoesNotExist:
                raise CommandError('User "%s" does not exist' % username)

            for device in devices_for_user(user):
                device.delete()
