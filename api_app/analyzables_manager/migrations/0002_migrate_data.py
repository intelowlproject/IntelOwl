import hashlib

from django.db import migrations
from django.db.models import F, OuterRef, Subquery, Window
from django.db.models.functions import RowNumber


def calculate_sha1(value: bytes) -> str:
    return hashlib.sha1(value).hexdigest()  # skipcq BAN-B324


def calculate_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()  # skipcq BAN-B324


def migrate(apps, schema_editor):
    Job = apps.get_model("api_app", "Job")
    Analyzable = apps.get_model("analyzables_manager", "Analyzable")
    # get only on job for md5
    jobs = Job.objects.alias(
        row_number=Window(
            RowNumber(), partition_by=(F("md5"),), order_by="received_request_time"
        )
    ).filter(row_number=1)
    for job in jobs:
        if job.is_sample:
            an = Analyzable.objects.create(
                md5=job.md5,
                sha256=job.sha256,
                sha1=job.sha1,
                file=job.file,
                mimetype=job.file_mimetype,
                name=job.file_name,
                classification="sample",
                discovery_date=job.received_request_time,
            )

            p = job.file.path
            try:
                p.rename(p.parent / job.md5)
            except Exception:
                print(f"Error: unable to rename {job}")
            else:
                job.file.name = job.md5
            with open(p, "rb") as f:
                content = f.read()
                f.seek(0)
            an.sha1 = calculate_sha1(content)
            an.sha256 = calculate_sha256(content)
        else:
            an = Analyzable.objects.create(
                md5=job.md5,
                name=job.observable_name,
                classification=job.observable_classification,
                discovery_date=job.received_request_time,
            )
            an.sha1 = calculate_sha1(an.name.encode("utf-8"))
            an.sha256 = calculate_sha256(an.name.encode("utf-8"))
        an.save()
    Job.objects.update(
        analyzable=Subquery(
            Analyzable.objects.filter(md5=OuterRef("md5")).values("pk")[:1]
        )
    )


class Migration(migrations.Migration):

    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("api_app", "0067_add_analyzable"),
        ("analyzables_manager", "0001_initial"),
        ("visualizers_manager", "0040_visualizer_config_data_model"),
    ]

    operations = [
        migrations.RunPython(migrate, migrations.RunPython.noop),
    ]
