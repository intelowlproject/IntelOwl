from django.db import migrations

connectors = {
    "MISP": {
        "disabled": False,
        "run_on_failure": False,
        "description": "Automatically creates an event on your MISP instance, linking the successful analysis on "
                       "IntelOwl",
        "python_module": "misp.MISP",
        "maximum_tlp": "WHITE",
        "config": {
            "soft_time_limit": 30,
            "queue": "default"
        },
        "secrets": {
            "api_key_name": {
                "env_var_key": "CONNECTOR_MISP_KEY",
                "description": "API key for your MISP instance",
                "type": "str",
                "required": True
            },
            "url_key_name": {
                "env_var_key": "CONNECTOR_MISP_URL",
                "description": "URL of your MISP instance",
                "type": "str",
                "required": True
            }
        },
        "params": {
            "ssl_check": {
                "value": True,
                "type": "bool",
                "description": "Enable SSL certificate server verification. Change this if your MISP instance has not"
                               " SSL enabled."
            },
            "self_signed_certificate": {
                "value": False,
                "type": "bool",
                "description": "If ssl_check and this flag are True, the analyzer will leverage a CA_BUNDLE to "
                               "authenticate against the MISP instance. IntelOwl will look for it at this path: "
                               "`<project_location>/configuration/misp_ssl.crt`. Remember that this file should be "
                               "readable by the application (`www-data` user must read this)"
            },
            "debug": {
                "value": False,
                "type": "bool",
                "description": "Enable debug logs."
            },
            "tlp": {
                "value": "white",
                "type": "str",
                "description": "Change this as per your organization's threat sharing conventions."
            }
        }
    },
    "OpenCTI": {
        "disabled": False,
        "run_on_failure": False,
        "description": "Automatically creates an observable and a linked report on your OpenCTI instance, linking the "
                       "successful analysis on IntelOwl",
        "python_module": "opencti.OpenCTI",
        "maximum_tlp": "WHITE",
        "config": {
            "soft_time_limit": 30,
            "queue": "default"
        },
        "secrets": {
            "api_key_name": {
                "env_var_key": "CONNECTOR_OPENCTI_KEY",
                "description": "API key for your OpenCTI instance",
                "required": True,
                "type": "str",
            },
            "url_key_name": {
                "env_var_key": "CONNECTOR_OPENCTI_URL",
                "description": "URL of your OpenCTI instance",
                "required": True,
                "type": "str",
            }
        },
        "params": {
            "ssl_verify": {
                "value": True,
                "type": "bool",
                "description": "Enable SSL certificate server verification. Change this if your OpenCTI instance has "
                               "not SSL enabled."
            },
            "proxies": {
                "value": {
                    "http": "",
                    "https": ""
                },
                "type": "dict",
                "description": "Use these options to pass your request through a proxy server."
            },
            "tlp": {
                "value": {
                    "type": "white",
                    "color": "#ffffff",
                    "x_opencti_order": 1
                },
                "type": "dict",
                "description": "Change this as per your organization's threat sharing conventions."
            }
        }
    },
    "YETI": {
        "disabled": False,
        "run_on_failure": True,
        "description": "find or create observable on YETI, linking the successful analysis on IntelOwl.",
        "python_module": "yeti.YETI",
        "maximum_tlp": "WHITE",
        "config": {
            "soft_time_limit": 30,
            "queue": "default"
        },
        "secrets": {
            "api_key_name": {
                "env_var_key": "CONNECTOR_YETI_KEY",
                "description": "API key for your YETI instance",
                "required": True,
                "type": "str",
            },
            "url_key_name": {
                "env_var_key": "CONNECTOR_YETI_URL",
                "description": "API URL of your YETI instance",
                "required": True,
                "type": "str",
            }
        },
        "params": {
            "verify_ssl": {
                "value": True,
                "type": "bool",
                "description": "Enable SSL certificate server verification. Change this if your YETI instance has not"
                               " SSL enabled."
            }
        }
    }
}


def create_configurations(apps, schema_editor):
    ConnectorConfig = apps.get_model("connectors_manager", "ConnectorConfig")
    for connector_name, connector in connectors.items():
        cc = ConnectorConfig(
            name=connector_name,
            **connector
        )
        cc.full_clean()
        cc.save()


def delete_configurations(apps, schema_editor):
    ConnectorConfig = apps.get_model("connectors_manager", "ConnectorConfig")
    ConnectorConfig.objects.all().delete()


class Migration(migrations.Migration):

    dependencies = [
        ('connectors_manager', '0003_connectorconfig'),
    ]

    operations = [
        migrations.RunPython(
            create_configurations, delete_configurations
        ),
    ]
