from django.db import migrations


def migrate(apps, schema_editor):
    Job = apps.get_model("api_app", "Job")
    Analyzable = apps.get_model("analyzables_manager", "Analyzable")
    for job in Job.objects.all().order_by("received_request_time"):
        if job.is_sample:
            obj, created = Analyzable.objects.get_or_create(
                md5=job.md5,
                defaults={
                    "file": job.file,
                    "mimetype": job.file_mimetype,
                    "name": job.file_name,
                    "md5": job.md5,
                    "classification": "sample",
                    "discovery_date": job.received_request_time,
                },
            )
            if created:
                p = job.file.path
                try:
                    p.rename(p.parent / job.md5)
                except Exception:
                    ...
                else:
                    job.file.name = job.md5
        else:
            obj, created = Analyzable.objects.get_or_create(
                md5=job.md5,
                defaults={
                    "name": job.observable_name,
                    "md5": job.md5,
                    "classification": job.observable_classification,
                    "discovery_date": job.received_request_time,
                },
            )
        if created:
            obj.full_clean()
            obj.save()
        job.analyzable = obj
        job.save()


class Migration(migrations.Migration):

    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("api_app", "0067_add_analyzable"),
        ("analyzables_manager", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(migrate, migrations.RunPython.noop),
    ]
