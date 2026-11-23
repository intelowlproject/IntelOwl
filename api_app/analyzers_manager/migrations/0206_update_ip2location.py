# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations

DESCRIPTION = (
    "[API Docs](https://www.ip2location.io/ip2location-documentation) "
    "IP2Location.io looks up an IP address in real time, with or without an API key. "
    "Keyless access allows 1,000 queries per day. A free API key allows 50,000 queries "
    "per month. Free and keyless responses include basic geolocation, ASN, and a boolean "
    "is_proxy flag. Detailed proxy fields (proxy_type, is_vpn, is_tor, is_data_center, "
    "is_residential_proxy, provider, and the rest of the proxy object) require the "
    "IP2Location.io Security plan."
)

KEY_DESCRIPTION = (
    "Optional IP2Location.io API key. Leave empty for keyless access "
    "(1,000 queries per day). A free key allows 50,000 queries per month. "
    "Required only when api_version is keyed."
)

VERSION_DESCRIPTION = (
    "keyed or keyless. Defaults to keyless (no API key, 1,000 queries per day). "
    "keyed sends api_key_name (a free key allows 50,000 queries per month). "
    "Detailed proxy fields (proxy_type, is_vpn, is_tor, is_data_center, "
    "is_residential_proxy, provider, and the rest of the proxy object) require "
    "the IP2Location.io Security plan. Free and keyless responses include only "
    "the basic is_proxy flag."
)

OLD_DESCRIPTION = (
    "[API Docs](https://www.ip2location.io/ip2location-documentation) "
    "IP2Location.io allows users to check IP address location in real time. "
    "(Supports both with or without key)"
)

# asn is applied in Ip2location._update_data_model. The API returns it as a
# string, and a missing value is "-", which is not a valid integer.
MAPPING = {
    "country_code": "country_code",
    "as": "isp",
}


def _module(apps):
    PythonModule = apps.get_model("api_app", "PythonModule")
    return PythonModule.objects.filter(
        module="ip2location.Ip2location",
        base_path="api_app.analyzers_manager.observable_analyzers",
    ).first()


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    module = _module(apps)
    if module is None:
        return

    Parameter.objects.filter(python_module=module, name="api_key_name").update(
        required=False,
        description=KEY_DESCRIPTION,
    )
    Parameter.objects.filter(python_module=module, name="api_version").update(
        description=VERSION_DESCRIPTION,
    )

    config = AnalyzerConfig.objects.filter(name="Ip2location").first()
    if config is None:
        return
    config.description = DESCRIPTION
    config.mapping_data_model = MAPPING
    config.save(update_fields=["description", "mapping_data_model"])

    version = Parameter.objects.filter(python_module=module, name="api_version").first()
    if version is None:
        return
    already_default = PluginConfig.objects.filter(
        parameter=version,
        analyzer_config=config,
        owner=None,
        for_organization=False,
    ).exists()
    if not already_default:
        PluginConfig.objects.create(
            parameter=version,
            analyzer_config=config,
            owner=None,
            for_organization=False,
            value="keyless",
        )


def reverse_migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    module = _module(apps)
    if module is None:
        return

    Parameter.objects.filter(python_module=module, name="api_key_name").update(
        required=True,
        description="Ip2location API key name.",
    )
    Parameter.objects.filter(python_module=module, name="api_version").update(
        description="Ip2location API version keyed or keyless.",
    )

    config = AnalyzerConfig.objects.filter(name="Ip2location").first()
    if config is None:
        return
    config.description = OLD_DESCRIPTION
    config.mapping_data_model = {}
    config.save(update_fields=["description", "mapping_data_model"])

    version = Parameter.objects.filter(python_module=module, name="api_version").first()
    if version is None:
        return
    PluginConfig.objects.filter(
        parameter=version,
        analyzer_config=config,
        owner=None,
        for_organization=False,
        value="keyless",
    ).delete()


class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ("api_app", "0073_alter_updatecheckstatus_last_checked_at_and_more"),
        ("analyzers_manager", "0205_analyzer_config_ip2location_lite"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
