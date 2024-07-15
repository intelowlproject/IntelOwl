from django.conf import settings
from django.db import migrations


def migrate(apps, schema_editor):
    User = apps.get_model(*settings.AUTH_USER_MODEL.split("."))
    UserProfile = apps.get_model("authentication", "UserProfile")
    IngestorConfig = apps.get_model("ingestors_manager", "IngestorConfig")
    PluginConfig = apps.get_model("api_app", "PluginConfig")

    users = User.objects.filter(username__endswith="Ingestor")
    for u in users:
        username = u.username.removesuffix("Ingestor")
        if username != username.title():
            correct_user = User.objects.get_or_create(
                username=f"{username.title()}Ingestor"
            )[0]
            if not hasattr(correct_user, "profile"):
                correct_user.profile = UserProfile()
                correct_user.profile.task_priority = 7
                correct_user.profile.is_robot = True
                correct_user.profile.save()

            related_ingestor = IngestorConfig.objects.get(name__iexact=username)
            related_ingestor.user = correct_user
            related_ingestor.save()

            for pc in PluginConfig.objects.filter(owner=u):
                pc.owner = correct_user
                pc.save()

            u.delete()


def reverse_migrate(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ("api_app", "0062_alter_parameter_python_module"),
        ("ingestors_manager", "0021_ingestor_fix_malwarebazaar_threatfox"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
