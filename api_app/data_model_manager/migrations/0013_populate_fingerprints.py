import hashlib
import json
import logging

from django.db import migrations

logger = logging.getLogger(__name__)

def normalize_dict(obj):
    if isinstance(obj, dict):
        return {k: normalize_dict(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [normalize_dict(i) for i in obj]
    return obj

def generate_fingerprint_from_instance(instance):
    data = {}
    for field in instance._meta.fields:
        name = field.name
        if name in ["id", "date", "fingerprint"]:
            continue
        value = getattr(instance, name)
        if hasattr(value, "isoformat"):
            value = value.isoformat()
        data[name] = value
    normalized_data = normalize_dict(data)
    encoded_data = json.dumps(normalized_data, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded_data).hexdigest()

def populate_fingerprints(apps, schema_editor):
    batch_size = 500
    for model_name in ["IPDataModel", "DomainDataModel", "FileDataModel"]:
        Model = apps.get_model("data_model_manager", model_name)
        queryset = Model.objects.filter(fingerprint="").iterator(chunk_size=batch_size)
        batch = []
        for instance in queryset:
            try:
                instance.fingerprint = generate_fingerprint_from_instance(instance)
                batch.append(instance)
            except Exception as e:
                logger.error(f"Failed to generate fingerprint for {model_name} {instance.pk}: {e}")
            if len(batch) >= batch_size:
                Model.objects.bulk_update(batch, ["fingerprint"])
                batch = []
        if batch:
            Model.objects.bulk_update(batch, ["fingerprint"])
        from django.contrib.contenttypes.models import ContentType
        ct, _ = ContentType.objects.get_or_create(app_label="data_model_manager", model=model_name.lower())
        from django.db.models import Count
        duplicates = Model.objects.values("fingerprint").annotate(c=Count("id")).filter(c__gt=1)
        for entry in duplicates:
            fp = entry["fingerprint"]
            if not fp:
                continue
            instances = list(Model.objects.filter(fingerprint=fp).order_by("date"))
            canonical = instances[0]
            redundant_ids = [r.id for r in instances[1:]]
            AnalyzerReport = apps.get_model("analyzers_manager", "AnalyzerReport")
            AnalyzerReport.objects.filter(
                data_model_content_type_id=ct.id,
                data_model_object_id__in=redundant_ids
            ).update(data_model_object_id=canonical.id)
            Job = apps.get_model("api_app", "Job")
            Job.objects.filter(
                data_model_content_type_id=ct.id,
                data_model_object_id__in=redundant_ids
            ).update(data_model_object_id=canonical.id)
            try:
                UserAnalyzableEvent = apps.get_model("user_events_manager", "UserAnalyzableEvent")
                UserAnalyzableEvent.objects.filter(
                    data_model_content_type_id=ct.id,
                    data_model_object_id__in=redundant_ids
                ).update(data_model_object_id=canonical.id)
            except LookupError:
                pass
            Model.objects.filter(id__in=redundant_ids).delete()

def reverse_populate_fingerprints(apps, schema_editor):
    pass

class Migration(migrations.Migration):
    dependencies = [
        ('data_model_manager', '0012_domaindatamodel_fingerprint_and_more'),
    ]
    operations = [
        migrations.RunPython(populate_fingerprints, reverse_populate_fingerprints),
    ]
