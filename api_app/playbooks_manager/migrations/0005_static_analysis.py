from django.db import migrations
from django.db.models.fields.related_descriptors import ManyToManyDescriptor

objects = [{"model": "playbooks_manager.playbookconfig", "pk": "Sample Static Analsis", "fields": {"type": "[\"file\"]", "description": "Execute a static analysis", "disabled": False, "runtime_configuration": {"analyzers": {}, "connectors": {}}, "analyzers": ["Rtf_Info", "APKiD_Scan_APK_DEX_JAR", "Doc_Info", "ClamAV", "Cymru_Hash_Registry_Get_File", "OneNote_Info", "MalwareBazaar_Get_File", "YARAify_File_Search", "PDF_Info", "BoxJS_Scan_JavaScript", "HybridAnalysis_Get_File", "Yara", "OTX_Check_Hash"], "connectors": []}}]


def migrate(apps, schema_editor):
    for obj in objects:
        python_path = obj["model"]
        Model = apps.get_model(*python_path.split("."))
        no_mtm = {}
        mtm = {}
        for field, value in obj["fields"].items():
            if type(getattr(Model, field)) != ManyToManyDescriptor:
                no_mtm[field] = value
            else:
                mtm[field] = value
        o = Model(**no_mtm, pk=obj["pk"])
        o.full_clean()
        o.save()
        for field, value in mtm.items():
            attribute = getattr(o, field)
            attribute.set(value)


def reverse_migrate(apps, schema_editor):
    for obj in objects:
        python_path = obj["model"]
        Model = apps.get_model(*python_path.split("."))
        Model.objects.get(pk=obj["pk"]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('playbooks_manager', '0004_datamigration'),
    ]

    operations = [
        migrations.RunPython(
            migrate, reverse_migrate
        ),
    ]
