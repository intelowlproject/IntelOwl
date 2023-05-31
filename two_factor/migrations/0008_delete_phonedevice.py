from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("two_factor", "0007_auto_20201201_1019"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.DeleteModel(
                    name="PhoneDevice",
                ),
            ],
        ),
    ]
