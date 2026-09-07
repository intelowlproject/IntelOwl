from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('data_model_manager', '0011_data_model_date_index'),
    ]

    operations = [
        migrations.AddField(
            model_name='domaindatamodel',
            name='fingerprint',
            field=models.CharField(blank=True, db_index=True, max_length=64, default=''),
        ),
        migrations.AddField(
            model_name='filedatamodel',
            name='fingerprint',
            field=models.CharField(blank=True, db_index=True, max_length=64, default=''),
        ),
        migrations.AddField(
            model_name='ipdatamodel',
            name='fingerprint',
            field=models.CharField(blank=True, db_index=True, max_length=64, default=''),
        ),
    ]
