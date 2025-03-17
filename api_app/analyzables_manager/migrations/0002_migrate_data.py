import hashlib
import io

from django.core.files import File
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
    jobs = (
        Job.objects.alias(
            row_number=Window(
                RowNumber(), partition_by=(F("md5"),), order_by="received_request_time"
            )
        )
        .filter(row_number=1)
        .order_by("pk")
        .exclude(md5__in=Analyzable.objects.values_list("md5", flat=True))
    )
    print(f"There are {jobs.count()} jobs to migrate")
    for i, job in enumerate(jobs):
        print(f"Migrating job {i} {job.md5}", flush=True)
        if job.is_sample:
            content = job.file.read()
            an = Analyzable.objects.create(
                md5=job.md5,
                file=File(io.BytesIO(content), name=job.md5),
                mimetype=job.file_mimetype,
                name=job.file_name[:255],
                classification="file",
                discovery_date=job.received_request_time,
            )

            an.sha1 = calculate_sha1(content)
            an.sha256 = calculate_sha256(content)
        else:
            an = Analyzable.objects.create(
                md5=job.md5,
                name=job.observable_name[:255],
                classification=job.observable_classification,
                discovery_date=job.received_request_time,
            )
            an.sha1 = calculate_sha1(an.name.encode("utf-8"))
            an.sha256 = calculate_sha256(an.name.encode("utf-8"))
        an.save()
    print("Done analyzable creation")
    Job.objects.update(
        analyzable=Subquery(
            Analyzable.objects.filter(md5=OuterRef("md5")).values("pk")[:1]
        )
    )
    print("Done update of jobs")


class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("api_app", "0067_add_analyzable"),
        ("analyzables_manager", "0001_initial"),
        ("visualizers_manager", "0040_visualizer_config_data_model"),
    ]

    operations = [
        migrations.RunPython(migrate, migrations.RunPython.noop),
    ]
