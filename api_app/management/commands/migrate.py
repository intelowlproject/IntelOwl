from django.core.management.base import no_translations
from django.core.management.commands.migrate import Command as MigrateCommand


class Command(MigrateCommand):
    @no_translations
    def handle(self, *args, **options):
        super().handle(*args, **options)
        from api_app.signals import migrate_finished

        migrate_finished.send(self, **options)
