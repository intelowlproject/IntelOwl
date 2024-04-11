from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

old_plugin = {'id': 1, 'python_module': {'health_check_schedule': None, 'update_schedule': {'minute': '30', 'hour': '7', 'day_of_week': '*', 'day_of_month': '*', 'month_of_year': '*'}, 'module': 'threatfox.ThreatFox', 'base_path': 'api_app.ingestors_manager.ingestors'}, 'schedule': {'minute': '30', 'hour': '7', 'day_of_week': '*', 'day_of_month': '*', 'month_of_year': '*'}, 'periodic_task': {'crontab': {'minute': '30', 'hour': '7', 'day_of_week': '*', 'day_of_month': '*', 'month_of_year': '*'}, 'name': 'ThreatFoxIngestor', 'task': 'intel_owl.tasks.execute_ingestor', 'kwargs': '{"config_pk": "ThreatFox"}', 'queue': 'default', 'enabled': False}, 'user': {'username': 'ThreatFoxIngestor', 'first_name': '', 'last_name': '', 'email': ''}, 'name': 'ThreatFox', 'description': 'Threatfox ingestor', 'disabled': True, 'soft_time_limit': 60, 'routing_key': 'default', 'health_check_status': True, 'maximum_jobs': 10, 'delay': '00:00:00', 'health_check_task': None, 'playbook_to_execute': 3, 'model': 'ingestors_manager.IngestorConfig'}
old_params = [{'python_module': {'module': 'threatfox.ThreatFox', 'base_path': 'api_app.ingestors_manager.ingestors'}, 'name': 'days', 'type': 'int', 'description': 'Days to check. From 1 to 7', 'is_secret': False, 'required': True}]
old_values = [{'parameter': {'python_module': {'module': 'threatfox.ThreatFox', 'base_path': 'api_app.ingestors_manager.ingestors'}, 'name': 'days', 'type': 'int', 'description': 'Days to check. From 1 to 7', 'is_secret': False, 'required': True}, 'analyzer_config': None, 'connector_config': None, 'visualizer_config': None, 'ingestor_config': 'ThreatFox', 'pivot_config': None, 'for_organization': False, 'value': 1, 'updated_at': '2024-04-11T15:28:34.851708Z', 'owner': None}]

new_plugin = {'id': 1, 'python_module': {'health_check_schedule': None, 'update_schedule': {'minute': '30', 'hour': '7', 'day_of_week': '*', 'day_of_month': '*', 'month_of_year': '*'}, 'module': 'threatfox.ThreatFox', 'base_path': 'api_app.ingestors_manager.ingestors'}, 'schedule': {'minute': '30', 'hour': '7', 'day_of_week': '*', 'day_of_month': '*', 'month_of_year': '*'}, 'periodic_task': {'crontab': {'minute': '30', 'hour': '7', 'day_of_week': '*', 'day_of_month': '*', 'month_of_year': '*'}, 'name': 'ThreatfoxIngestor', 'task': 'intel_owl.tasks.execute_ingestor', 'kwargs': '{"config_name": "ThreatFox"}', 'queue': 'default', 'enabled': False}, 'user': {'username': 'ThreatfoxIngestor', 'first_name': '', 'last_name': '', 'email': ''}, 'name': 'ThreatFox', 'description': 'Threatfox ingestor', 'disabled': True, 'soft_time_limit': 60, 'routing_key': 'default', 'health_check_status': True, 'maximum_jobs': 10, 'delay': '00:00:00', 'health_check_task': None, 'playbook_to_execute': 3, 'model': 'ingestors_manager.IngestorConfig'}
new_params = [{'python_module': {'module': 'threatfox.ThreatFox', 'base_path': 'api_app.ingestors_manager.ingestors'}, 'name': 'days', 'type': 'int', 'description': 'Days to check. From 1 to 7', 'is_secret': False, 'required': True}, {'python_module': {'module': 'threatfox.ThreatFox', 'base_path': 'api_app.ingestors_manager.ingestors'}, 'name': 'url', 'type': 'str', 'description': 'API endpoint', 'is_secret': False, 'required': True}]
new_values = [{'parameter': {'python_module': {'module': 'threatfox.ThreatFox', 'base_path': 'api_app.ingestors_manager.ingestors'}, 'name': 'days', 'type': 'int', 'description': 'Days to check. From 1 to 7', 'is_secret': False, 'required': True}, 'analyzer_config': None, 'connector_config': None, 'visualizer_config': None, 'ingestor_config': 'ThreatFox', 'pivot_config': None, 'for_organization': False, 'value': 1, 'updated_at': '2024-04-11T14:55:11.772272Z', 'owner': None}, {'parameter': {'python_module': {'module': 'threatfox.ThreatFox', 'base_path': 'api_app.ingestors_manager.ingestors'}, 'name': 'url', 'type': 'str', 'description': 'API endpoint', 'is_secret': False, 'required': True}, 'analyzer_config': None, 'connector_config': None, 'visualizer_config': None, 'ingestor_config': 'ThreatFox', 'pivot_config': None, 'for_organization': False, 'value': 'https://threatfox-api.abuse.ch/api/v1/', 'updated_at': '2024-04-11T14:57:13.545029Z', 'owner': None}]

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
                    value = other_model.objects.get(name=new_plugin["name"])
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
    PythonModule = apps.get_model("api_app", "PythonModule")
    python_path = new_plugin.pop("model")
    Model = apps.get_model(*python_path.split("."))

    pm = PythonModule.objects.get(
        module="threatfox.ThreatFox", base_path="api_app.ingestors_manager.ingestors"
    )
    p1 = Parameter(
        name="url",
        type="str",
        description="API endpoint",
        is_secret=False,
        required=True,
        python_module=pm,
    )
    p1.full_clean()
    p1.save()

    if (obj := Model.objects.filter(name=new_plugin["name"])).exists():
        obj.delete()

    exists = _create_object(Model, new_plugin)
    if not exists:
        for param in new_params:
            _create_object(Parameter, param)
        for value in new_values:
            _create_object(PluginConfig, value)



def reverse_migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    PythonModule = apps.get_model("api_app", "PythonModule")
    python_path = new_plugin.pop("model")
    Model = apps.get_model(*python_path.split("."))

    Model.objects.get(name=new_plugin["name"]).delete()

    pm = PythonModule.objects.get(
        module="threatfox.ThreatFox", base_path="api_app.ingestors_manager.ingestors"
    )
    parameter = Parameter.objects.get(
        name="url", python_module__pk=pm.python_module_id
    )
    parameter.delete()

    exists = _create_object(Model, old_plugin)
    if not exists:
        for param in old_params:
            _create_object(Parameter, param)
        for value in old_values:
            _create_object(PluginConfig, value)


class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ('api_app', '0062_alter_parameter_python_module'),
        ('ingestors_manager', '0019_ingestor_config_malwarebazaar'),
    ]

    operations = [
        migrations.RunPython(
            migrate, reverse_migrate
        )
    ]
        
        