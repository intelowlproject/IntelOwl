from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
    ReverseManyToOneDescriptor,
    ReverseOneToOneDescriptor,
)

plugin = {'python_module': {'health_check_schedule': None, 'update_schedule': None, 'module': 'sogen.Sogen', 'base_path': 'api_app.analyzers_manager.file_analyzers'}, 'name': 'Sogen', 'description': "Emulates PE binary execution using the Sogen emulator (https://github.com/momo5502/sogen) to capture runtime behavior: module loads, entry point execution, and exit status. Runs as a Docker-based sidecar service since Sogen's native build requires compiling a bundled QEMU/Unicorn/SDL fork from source.", 'disabled': False, 'soft_time_limit': 120, 'routing_key': 'default', 'health_check_status': True, 'type': 'file', 'docker_based': True, 'maximum_tlp': 'RED', 'observable_supported': [], 'supported_filetypes': ['application/vnd.microsoft.portable-executable'], 'run_hash': False, 'run_hash_type': '', 'not_supported_filetypes': [], 'mapping_data_model': {}, 'model': 'analyzers_manager.AnalyzerConfig'}

params = [{'python_module': {'module': 'sogen.Sogen', 'base_path': 'api_app.analyzers_manager.file_analyzers'}, 'name': 'max_instructions', 'type': 'int', 'description': 'Maximum instruction count before halting emulation', 'is_secret': False, 'required': False}, {'python_module': {'module': 'sogen.Sogen', 'base_path': 'api_app.analyzers_manager.file_analyzers'}, 'name': 'timeout_seconds', 'type': 'int', 'description': 'Emulation wall-clock timeout in seconds', 'is_secret': False, 'required': False}, {'python_module': {'module': 'sogen.Sogen', 'base_path': 'api_app.analyzers_manager.file_analyzers'}, 'name': 'requests_timeout', 'type': 'int', 'description': 'Python requests HTTP timeout in seconds', 'is_secret': False, 'required': False}, {'python_module': {'module': 'sogen.Sogen', 'base_path': 'api_app.analyzers_manager.file_analyzers'}, 'name': 'url_key_name', 'type': 'str', 'description': 'URL of the sogen_analyzer sidecar, e.g. http://sogen_analyzer:4009', 'is_secret': False, 'required': True}]

values = [{'parameter': {'python_module': {'module': 'sogen.Sogen', 'base_path': 'api_app.analyzers_manager.file_analyzers'}, 'name': 'url_key_name', 'type': 'str', 'description': 'URL of the sogen_analyzer sidecar, e.g. http://sogen_analyzer:4009', 'is_secret': False, 'required': True}, 'analyzer_config': 'Sogen', 'connector_config': None, 'visualizer_config': None, 'ingestor_config': None, 'pivot_config': None, 'for_organization': False, 'value': 'http://sogen_analyzer:4009', 'updated_at': '2026-08-16T09:43:33.346182Z', 'owner': None}]


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
        in [
            ForwardManyToOneDescriptor,
            ReverseManyToOneDescriptor,
            ReverseOneToOneDescriptor,
            ForwardOneToOneDescriptor,
        ]
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
        ('api_app', '0073_alter_updatecheckstatus_last_checked_at_and_more'),
        ('analyzers_manager', '0194_analyzer_config_rdap'),
    ]

    operations = [
        migrations.RunPython(
            migrate, reverse_migrate
        )
    ]
        
        