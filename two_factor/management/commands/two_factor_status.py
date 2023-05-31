from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from ...utils import default_device


class Command(BaseCommand):
    """
    Command to check two-factor authentication status for certain users.

    The command accepts any number of usernames, and will list if OTP is
    enabled or disabled for those users.

    Example usage::

        manage.py two_factor_status bouke steve
        bouke: enabled
        steve: disabled
    """

    help = "Checks two-factor authentication status for the given users"

    def add_arguments(self, parser):
        parser.add_argument("args", metavar="usernames", nargs="*")

    def handle(self, *usernames, **options):
        User = get_user_model()
        for username in usernames:
            try:
                user = User.objects.get_by_natural_key(username)
            except User.DoesNotExist:
                raise CommandError('User "%s" does not exist' % username)

            self.stdout.write(
                "%s: %s"
                % (
                    username,
                    "enabled" if default_device(user) else self.style.ERROR("disabled"),
                )
            )
