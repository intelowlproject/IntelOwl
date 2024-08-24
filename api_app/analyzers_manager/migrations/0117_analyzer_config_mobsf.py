from django.db import migrations, models
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

import api_app.fields

plugin = {
    "python_module": {
        "health_check_schedule": None,
        "update_schedule": None,
        "module": "mobsf.Mobsf",
        "base_path": "api_app.analyzers_manager.file_analyzers",
    },
    "name": "MobSF",
    "description": "[MobSF](https://github.com/MobSF/mobsfscan/) is a static analysis tool that can find insecure code patterns in your Android and iOS source code. Supports Java, Kotlin, Android XML, Swift and Objective C Code.",
    "disabled": False,
    "soft_time_limit": 10,
    "routing_key": "default",
    "health_check_status": True,
    "type": "file",
    "docker_based": False,
    "maximum_tlp": "RED",
    "observable_supported": [],
    "supported_filetypes": [
        "text/xml",
        "text/x-java",
        "text/x-kotlin",
        "text/x-swift",
        "text/x-objective-c",
    ],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": [],
    "model": "analyzers_manager.AnalyzerConfig",
}

params = []

values = []


def _get_real_obj(Model, field, value):
    def _get_obj(Model, other_model, value):
        if isinstance(value, dict):
            real_vals = {}
            for key, real_val in value.items():
                real_vals[key] = _get_real_obj(other_model, key, real_val)
            value = other_model.objects.get_or_create(**real_vals)[0]
        # it is just the primary key serialized
        else:
            if isinstance(value, int):
                if Model.__name__ == "PluginConfig":
                    value = other_model.objects.get(name=plugin["name"])
                else:
                    value = other_model.objects.get(pk=value)
            else:
                value = other_model.objects.get(name=value)
        return value

    if (
        type(getattr(Model, field))
        in [ForwardManyToOneDescriptor, ForwardOneToOneDescriptor]
        and value
    ):
        other_model = getattr(Model, field).get_queryset().model
        value = _get_obj(Model, other_model, value)
    elif type(getattr(Model, field)) in [ManyToManyDescriptor] and value:
        other_model = getattr(Model, field).rel.model
        value = [_get_obj(Model, other_model, val) for val in value]
    return value


def _create_object(Model, data):
    mtm, no_mtm = {}, {}
    for field, value in data.items():
        value = _get_real_obj(Model, field, value)
        if type(getattr(Model, field)) is ManyToManyDescriptor:
            mtm[field] = value
        else:
            no_mtm[field] = value
    try:
        o = Model.objects.get(**no_mtm)
    except Model.DoesNotExist:
        o = Model(**no_mtm)
        o.full_clean()
        o.save()
        for field, value in mtm.items():
            attribute = getattr(o, field)
            if value is not None:
                attribute.set(value)
        return False
    return True


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    python_path = plugin.pop("model")
    Model = apps.get_model(*python_path.split("."))
    if not Model.objects.filter(name=plugin["name"]).exists():
        exists = _create_object(Model, plugin)
        if not exists:
            for param in params:
                _create_object(Parameter, param)
            for value in values:
                _create_object(PluginConfig, value)


def reverse_migrate(apps, schema_editor):
    python_path = plugin.pop("model")
    Model = apps.get_model(*python_path.split("."))
    Model.objects.get(name=plugin["name"]).delete()


class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ("api_app", "0062_alter_parameter_python_module"),
        ("analyzers_manager", "0115_analyzer_config_knock"),
    ]

    operations = [
        migrations.AlterField(
            model_name="analyzerconfig",
            name="not_supported_filetypes",
            field=api_app.fields.ChoiceArrayField(
                base_field=models.CharField(
                    choices=[
                        ("application/w-script-file", "Wscript"),
                        ("application/javascript", "Javascript1"),
                        ("application/x-javascript", "Javascript2"),
                        ("text/javascript", "Javascript3"),
                        ("application/x-vbscript", "Vb Script"),
                        ("text/x-ms-iqy", "Iqy"),
                        ("application/vnd.android.package-archive", "Apk"),
                        ("application/x-dex", "Dex"),
                        ("application/onenote", "One Note"),
                        ("application/zip", "Zip1"),
                        ("multipart/x-zip", "Zip2"),
                        ("application/java-archive", "Java"),
                        ("text/rtf", "Rtf1"),
                        ("application/rtf", "Rtf2"),
                        ("application/x-sharedlib", "Shared Lib"),
                        ("application/vnd.microsoft.portable-executable", "Exe"),
                        ("application/x-elf", "Elf"),
                        ("application/octet-stream", "Octet"),
                        ("application/vnd.tcpdump.pcap", "Pcap"),
                        ("application/pdf", "Pdf"),
                        ("text/html", "Html"),
                        ("application/x-mspublisher", "Pub"),
                        ("application/vnd.ms-excel.addin.macroEnabled", "Excel Macro1"),
                        (
                            "application/vnd.ms-excel.sheet.macroEnabled.12",
                            "Excel Macro2",
                        ),
                        ("application/vnd.ms-excel", "Excel1"),
                        ("application/excel", "Excel2"),
                        (
                            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            "Doc",
                        ),
                        ("application/xml", "Xml1"),
                        ("text/xml", "Xml2"),
                        ("application/encrypted", "Encrypted"),
                        ("text/plain", "Plain"),
                        ("text/csv", "Csv"),
                        (
                            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                            "Pptx",
                        ),
                        ("application/msword", "Word1"),
                        (
                            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            "Word2",
                        ),
                        ("application/vnd.ms-powerpoint", "Powerpoint"),
                        ("application/vnd.ms-office", "Office"),
                        ("application/x-binary", "Binary"),
                        ("application/x-macbinary", "Mac1"),
                        ("application/mac-binary", "Mac2"),
                        ("application/x-mach-binary", "Mac3"),
                        ("application/x-zip-compressed", "Compress1"),
                        ("application/x-compressed", "Compress2"),
                        ("application/vnd.ms-outlook", "Outlook"),
                        ("message/rfc822", "Eml"),
                        ("application/pkcs7-signature", "Pkcs7"),
                        ("application/x-pkcs7-signature", "Xpkcs7"),
                        ("multipart/mixed", "Mixed"),
                        ("text/x-shellscript", "X Shellscript"),
                        ("application/x-chrome-extension", "Crx"),
                        ("application/json", "Json"),
                        ("application/x-executable", "Executable"),
                        ("text/x-java", "Java2"),
                        ("text/x-kotlin", "Kotlin"),
                        ("text/x-swift", "Swift"),
                        ("text/x-objective-c", "Objective C"),
                    ],
                    max_length=90,
                ),
                blank=True,
                default=list,
                size=None,
            ),
        ),
        migrations.AlterField(
            model_name="analyzerconfig",
            name="supported_filetypes",
            field=api_app.fields.ChoiceArrayField(
                base_field=models.CharField(
                    choices=[
                        ("application/w-script-file", "Wscript"),
                        ("application/javascript", "Javascript1"),
                        ("application/x-javascript", "Javascript2"),
                        ("text/javascript", "Javascript3"),
                        ("application/x-vbscript", "Vb Script"),
                        ("text/x-ms-iqy", "Iqy"),
                        ("application/vnd.android.package-archive", "Apk"),
                        ("application/x-dex", "Dex"),
                        ("application/onenote", "One Note"),
                        ("application/zip", "Zip1"),
                        ("multipart/x-zip", "Zip2"),
                        ("application/java-archive", "Java"),
                        ("text/rtf", "Rtf1"),
                        ("application/rtf", "Rtf2"),
                        ("application/x-sharedlib", "Shared Lib"),
                        ("application/vnd.microsoft.portable-executable", "Exe"),
                        ("application/x-elf", "Elf"),
                        ("application/octet-stream", "Octet"),
                        ("application/vnd.tcpdump.pcap", "Pcap"),
                        ("application/pdf", "Pdf"),
                        ("text/html", "Html"),
                        ("application/x-mspublisher", "Pub"),
                        ("application/vnd.ms-excel.addin.macroEnabled", "Excel Macro1"),
                        (
                            "application/vnd.ms-excel.sheet.macroEnabled.12",
                            "Excel Macro2",
                        ),
                        ("application/vnd.ms-excel", "Excel1"),
                        ("application/excel", "Excel2"),
                        (
                            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            "Doc",
                        ),
                        ("application/xml", "Xml1"),
                        ("text/xml", "Xml2"),
                        ("application/encrypted", "Encrypted"),
                        ("text/plain", "Plain"),
                        ("text/csv", "Csv"),
                        (
                            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                            "Pptx",
                        ),
                        ("application/msword", "Word1"),
                        (
                            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            "Word2",
                        ),
                        ("application/vnd.ms-powerpoint", "Powerpoint"),
                        ("application/vnd.ms-office", "Office"),
                        ("application/x-binary", "Binary"),
                        ("application/x-macbinary", "Mac1"),
                        ("application/mac-binary", "Mac2"),
                        ("application/x-mach-binary", "Mac3"),
                        ("application/x-zip-compressed", "Compress1"),
                        ("application/x-compressed", "Compress2"),
                        ("application/vnd.ms-outlook", "Outlook"),
                        ("message/rfc822", "Eml"),
                        ("application/pkcs7-signature", "Pkcs7"),
                        ("application/x-pkcs7-signature", "Xpkcs7"),
                        ("multipart/mixed", "Mixed"),
                        ("text/x-shellscript", "X Shellscript"),
                        ("application/x-chrome-extension", "Crx"),
                        ("application/json", "Json"),
                        ("application/x-executable", "Executable"),
                        ("text/x-java", "Java2"),
                        ("text/x-kotlin", "Kotlin"),
                        ("text/x-swift", "Swift"),
                        ("text/x-objective-c", "Objective C"),
                    ],
                    max_length=90,
                ),
                blank=True,
                default=list,
                size=None,
            ),
        ),
        migrations.RunPython(migrate, reverse_migrate),
    ]
