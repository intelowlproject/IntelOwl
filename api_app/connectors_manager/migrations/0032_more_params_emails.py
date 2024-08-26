from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

params = [
    {
        "python_module": {
            "module": "abuse_submitter.AbuseSubmitter",
            "base_path": "api_app.connectors_manager.connectors",
        },
        "name": "CCs",
        "type": "list",
        "description": "List of email addresses that will be added in CC",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "email_sender.EmailSender",
            "base_path": "api_app.connectors_manager.connectors",
        },
        "name": "CCs",
        "type": "list",
        "description": "List of email addresses that will be added in CC",
        "is_secret": False,
        "required": False,
    },
]

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
    for param in params:
        _create_object(Parameter, param)


class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ("api_app", "0062_alter_parameter_python_module"),
        ("connectors_manager", "0031_connector_config_abusesubmitter"),
    ]

    operations = [migrations.RunPython(migrate, migrations.RunPython.noop)]
