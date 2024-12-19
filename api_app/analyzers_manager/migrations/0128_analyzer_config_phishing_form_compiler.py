from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
    ReverseManyToOneDescriptor,
    ReverseOneToOneDescriptor,
)

plugin = {
    "python_module": {
        "health_check_schedule": None,
        "update_schedule": None,
        "module": "phishing.phishing_form_compiler.PhishingFormCompiler",
        "base_path": "api_app.analyzers_manager.file_analyzers",
    },
    "name": "Phishing_Form_Compiler",
    "description": "Analyzer that retrieves all forms in a web page and tries to compile and submit them.",
    "disabled": False,
    "soft_time_limit": 60,
    "routing_key": "default",
    "health_check_status": True,
    "type": "file",
    "docker_based": False,
    "maximum_tlp": "CLEAR",
    "observable_supported": [],
    "supported_filetypes": [
        "application/javascript",
        "application/octet-stream",
        "application/x-javascript",
        "text/javascript",
        "text/html",
    ],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": [],
    "model": "analyzers_manager.AnalyzerConfig",
}

params = [
    {
        "python_module": {
            "module": "phishing.phishing_form_compiler.PhishingFormCompiler",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "proxy_address",
        "type": "str",
        "description": "Address for proxy to use for requests.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "phishing.phishing_form_compiler.PhishingFormCompiler",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "xpath_form_selector",
        "type": "str",
        "description": "XPath expression to match a form on phishing page.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "phishing.phishing_form_compiler.PhishingFormCompiler",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "xpath_js_selector",
        "type": "str",
        "description": "XPath expression to match all js tag on phishing page.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "phishing.phishing_form_compiler.PhishingFormCompiler",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "name_matching",
        "type": "list",
        "description": 'List of values that should match the "name" attribute of "input" tag of type="text".\r\nMatching data will be replaced by a fake username.',
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "phishing.phishing_form_compiler.PhishingFormCompiler",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "cc_matching",
        "type": "list",
        "description": 'List of values that should match the "name" attribute of "input" tag of type="text".\r\nMatching data will be replaced by a fake credit card number.',
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "phishing.phishing_form_compiler.PhishingFormCompiler",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "pin_matching",
        "type": "list",
        "description": 'List of values that should match the "name" attribute of "input" tag of type="text".\r\nMatching data will be replaced by a fake credit card pin.',
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "phishing.phishing_form_compiler.PhishingFormCompiler",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "cvv_matching",
        "type": "list",
        "description": 'List of values that should match the "name" attribute of "input" tag of type="text".\r\nMatching data will be replaced by a fake credit card cvv/cvc.',
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "phishing.phishing_form_compiler.PhishingFormCompiler",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "expiration_date_matching",
        "type": "list",
        "description": 'List of values that should match the "name" attribute of "input" tag of type="text".\r\nMatching data will be replaced by a fake credit card expiration date.',
        "is_secret": False,
        "required": False,
    },
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "phishing.phishing_form_compiler.PhishingFormCompiler",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "proxy_address",
            "type": "str",
            "description": "Address for proxy to use for requests.",
            "is_secret": False,
            "required": False,
        },
        "analyzer_config": "Phishing_Form_Compiler",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
        "for_organization": False,
        "value": "",
        "updated_at": "2024-10-23T10:48:55.311636Z",
        "owner": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "phishing.phishing_form_compiler.PhishingFormCompiler",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "xpath_form_selector",
            "type": "str",
            "description": "XPath expression to match a form on phishing page.",
            "is_secret": False,
            "required": False,
        },
        "analyzer_config": "Phishing_Form_Compiler",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
        "for_organization": False,
        "value": "//*[self::form or self::iframe or self::fieldset][.//input[not(@type) or @type='' or @type='text']][.//input[@type='password']][.//input[@type='submit' or contains(@class, 'submit')] or .//button[not(@type) or @type='' or @type='submit' or contains(@class, 'submit')]]",
        "updated_at": "2024-10-23T10:48:55.289420Z",
        "owner": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "phishing.phishing_form_compiler.PhishingFormCompiler",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "xpath_js_selector",
            "type": "str",
            "description": "XPath expression to match all js tag on phishing page.",
            "is_secret": False,
            "required": False,
        },
        "analyzer_config": "Phishing_Form_Compiler",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
        "for_organization": False,
        "value": "//script[@type='text/javascript' or @type='' or (@src and not(contains(@src, 'jquery')))]",
        "updated_at": "2024-10-23T10:48:55.289420Z",
        "owner": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "phishing.phishing_form_compiler.PhishingFormCompiler",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "name_matching",
            "type": "list",
            "description": 'List of values that should match the "name" attribute of "input" tag of type="text".\r\nMatching data will be replaced by a fake username.',
            "is_secret": False,
            "required": False,
        },
        "analyzer_config": "Phishing_Form_Compiler",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
        "for_organization": False,
        "value": ["username", "user", "name", "first-name", "last-name"],
        "updated_at": "2024-10-23T13:07:03.010102Z",
        "owner": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "phishing.phishing_form_compiler.PhishingFormCompiler",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "cc_matching",
            "type": "list",
            "description": 'List of values that should match the "name" attribute of "input" tag of type="text".\r\nMatching data will be replaced by a fake credit card number.',
            "is_secret": False,
            "required": False,
        },
        "analyzer_config": "Phishing_Form_Compiler",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
        "for_organization": False,
        "value": ["card", "card_number", "card-number", "cc", "cc-number"],
        "updated_at": "2024-10-23T13:07:45.231863Z",
        "owner": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "phishing.phishing_form_compiler.PhishingFormCompiler",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "pin_matching",
            "type": "list",
            "description": 'List of values that should match the "name" attribute of "input" tag of type="text".\r\nMatching data will be replaced by a fake credit card pin.',
            "is_secret": False,
            "required": False,
        },
        "analyzer_config": "Phishing_Form_Compiler",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
        "for_organization": False,
        "value": ["pin"],
        "updated_at": "2024-10-23T13:07:57.878006Z",
        "owner": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "phishing.phishing_form_compiler.PhishingFormCompiler",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "cvv_matching",
            "type": "list",
            "description": 'List of values that should match the "name" attribute of "input" tag of type="text".\r\nMatching data will be replaced by a fake credit card cvv/cvc.',
            "is_secret": False,
            "required": False,
        },
        "analyzer_config": "Phishing_Form_Compiler",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
        "for_organization": False,
        "value": ["cvv", "cvc"],
        "updated_at": "2024-10-23T13:08:29.552992Z",
        "owner": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "phishing.phishing_form_compiler.PhishingFormCompiler",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "expiration_date_matching",
            "type": "list",
            "description": 'List of values that should match the "name" attribute of "input" tag of type="text".\r\nMatching data will be replaced by a fake credit card expiration date.',
            "is_secret": False,
            "required": False,
        },
        "analyzer_config": "Phishing_Form_Compiler",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
        "for_organization": False,
        "value": ["exp", "date", "expiration-date", "exp-date"],
        "updated_at": "2024-10-23T13:08:29.568943Z",
        "owner": None,
    },
]


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
        ("api_app", "0063_singleton_and_elastic_report"),
        ("analyzers_manager", "0127_analyzer_config_dshield"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
