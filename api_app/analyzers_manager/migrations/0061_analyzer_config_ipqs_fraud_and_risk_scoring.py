from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "python_module": {
        "module": "ipqs.IPQualityScore",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "name": "IPQS_Fraud_And_Risk_Scoring",
    "description": "Scan an Observable against IPQualityscore.",
    "disabled": False,
    "soft_time_limit": 60,
    "routing_key": "default",
    "health_check_status": True,
    "type": "observable",
    "docker_based": False,
    "maximum_tlp": "AMBER",
    "observable_supported": ["ip", "url", "domain", "generic"],
    "supported_filetypes": [],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": [],
    "health_check_task": None,
    "model": "analyzers_manager.AnalyzerConfig",
}

params = [
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "user_language",
        "type": "str",
        "description": 'You can optionally provide us with the user\'s language header. This allows us to evaluate the risk of the user as judged in the "fraud_score".',
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "user_agent",
        "type": "str",
        "description": 'You can optionally provide us with the user agent string (browser). This allows us to run additional checks to see if the user is a bot or running an invalid browser. This allows us to evaluate the risk of the user as judged in the "fraud_score".',
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "transaction_strictness",
        "type": "int",
        "description": "Adjusts the weights for penalties applied due to irregularities and fraudulent patterns detected on order and transaction details that can be optionally provided on each API request. This feature is only beneficial if you are passing order and transaction details. A table is available further down the page with supported transaction variables.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "ip_strictness",
        "type": "int",
        "description": 'How in depth (strict) do you want this query to be? Higher values take longer to process and may provide a higher false-positive rate. We recommend starting at "0", the lowest strictness setting, and increasing to "1" depending on your levels of fraud. Levels 2+ are VERY strict and will produce false-positives.',
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "mobile",
        "type": "bool",
        "description": "You can optionally specify that this lookup should be treated as a mobile device. Recommended for mobile lookups that do not have a user agent attached to the request. NOTE: This can cause unexpected and abnormal results if the device is not a mobile device.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "lighter_penalties",
        "type": "bool",
        "description": "Is your scoring too strict? Enable this setting to lower detection rates and Fraud Scores for mixed quality IP addresses. If you experience any false-positives with your traffic then enabling this feature will provide better results.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "ip_fast",
        "type": "bool",
        "description": "When this parameter is enabled our API will not perform certain forensic checks that take longer to process. Enabling this feature greatly increases the API speed without much impact on accuracy. This option is intended for services that require decision making in a time sensitive manner and can be used for any strictness level.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "allow_public_access_points",
        "type": "bool",
        "description": "Bypasses certain checks for IP addresses from education and research institutions, schools, and some corporate connections to better accommodate audiences that frequently use public connections.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "email_timeout",
        "type": "int",
        "description": 'Maximum number of seconds to wait for a reply from a mail service provider. If your implementation requirements do not need an immediate response, we recommend bumping this value to 20. Any results which experience a connection timeout will return the "timed_out" variable as true. Default value is 7 seconds.',
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "suggest_domain",
        "type": "bool",
        "description": 'Force analyze if the email address\'s domain has a typo and should be corrected to a popular mail service. By default, this test is currently only performed when the email is invalid or if the "recent abuse" status is true.',
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "email_strictness",
        "type": "int",
        "description": "Sets how strictly spam traps and honeypots are detected by our system, depending on how comfortable you are with identifying emails suspected of being a spam trap. 0 is the lowest level which will only return spam traps with high confidence. Strictness levels above 0 will return increasingly more strict results, with level 2 providing the greatest detection rates.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "email_fast",
        "type": "bool",
        "description": "When this parameter is enabled our API will not perform an SMTP check with the mail service provider, which greatly increases the API speed. A syntax check and DNS check (MX records, A records) are still performed on the email address as well as our email risk scoring which detects disposable email addresses. This option is intended for services that require decision making in a time sensitive manner.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "abuse_strictness",
        "type": "int",
        "description": 'Set the strictness level for machine learning pattern recognition of abusive email addresses with the "recent_abuse" data point. Default level of 0 provides good coverage, however if you are filtering account applications and facing advanced fraudsters then we recommend increasing this value to level 1 or 2.',
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "country",
        "type": "str",
        "description": "You can optionally provide us with the default country or countries this phone number is suspected to be associated with. Our system will prefer to use a country on this list for verification or will require a country to be specified in the event the phone number is less than 10 digits.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "ipqs_api_key",
        "type": "str",
        "description": "Your IPQS API key.",
        "is_secret": True,
        "required": True,
    },
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "url_timeout",
        "type": "int",
        "description": "Maximum number of seconds to perform live page scanning and follow redirects. If your implementation requirements do not need an immediate response, we recommend bumping this value to 5. Default value is 2 seconds.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "url_strictness",
        "type": "int",
        "description": 'How strict should we scan this URL? Stricter checks may provide a higher false-positive rate. We recommend defaulting to level "0", the lowest strictness setting, and increasing to "1" or "2" depending on your levels of abuse.',
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "url_fast",
        "type": "bool",
        "description": "When enabled, the API will provide quicker response times using lighter checks and analysis. This setting defaults to false.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "phone_strictness",
        "type": "int",
        "description": 'How in depth (strict) do you want this reputation check to be? Stricter checks may provide a higher false-positive rate. We recommend starting at "0", the lowest strictness setting, and increasing to "1" or "2" depending on your levels of fraud.',
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "enhanced_name_check",
        "type": "bool",
        "description": "Please contact support to activate enhanced name appending for a phone number. Our standard phone validation service already includes extensive name appending data.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ipqs.IPQualityScore",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "enhanced_line_check",
        "type": "bool",
        "description": 'Please contact support to activate this feature for more advanced active line checks through our HLR lookup service. This feature provides greater accuracy for identifying active or disconnected phone numbers including landline, mobile, and VOIP services. The "active_status" field is also populated when this feature is enabled.',
        "is_secret": False,
        "required": False,
    },
]

values = []


def _get_real_obj(Model, field, value):
    if (
        type(getattr(Model, field))
        in [ForwardManyToOneDescriptor, ForwardOneToOneDescriptor]
        and value
    ):
        other_model = getattr(Model, field).get_queryset().model
        # in case is a dictionary, we have to retrieve the object with every key
        if isinstance(value, dict):
            real_vals = {}
            for key, real_val in value.items():
                real_vals[key] = _get_real_obj(other_model, key, real_val)
            value = other_model.objects.get_or_create(**real_vals)[0]
        # it is just the primary key serialized
        else:
            value = other_model.objects.get(pk=value)
    return value


def _create_object(Model, data):
    mtm, no_mtm = {}, {}
    for field, value in data.items():
        if type(getattr(Model, field)) is ManyToManyDescriptor:
            mtm[field] = value
        else:
            value = _get_real_obj(Model, field, value)
            no_mtm[field] = value
    try:
        o = Model.objects.get(**no_mtm)
    except Model.DoesNotExist:
        o = Model(**no_mtm)
        o.full_clean()
        o.save()
        for field, value in mtm.items():
            attribute = getattr(o, field)
            attribute.set(value)


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    python_path = plugin.pop("model")
    Model = apps.get_model(*python_path.split("."))
    _create_object(Model, plugin)
    for param in params:
        _create_object(Parameter, param)
    for value in values:
        _create_object(PluginConfig, value)


def reverse_migrate(apps, schema_editor):
    python_path = plugin.pop("model")
    Model = apps.get_model(*python_path.split("."))
    Model.objects.get(name=plugin["name"]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0059_alter_organizationpluginconfiguration_unique_together"),
        ("analyzers_manager", "0060_analyzer_config_ip2location"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
