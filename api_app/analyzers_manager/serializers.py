from rest_framework import serializers as rfs

from api_app.analyzers_manager.models import AnalyzerReport
from api_app.helpers import map_data_type

from intel_owl.secrets import get_secret


class AnalyzerReportSerializer(rfs.ModelSerializer):
    class Meta:
        model = AnalyzerReport
        fields = "__all__"


class AnalyzerConfigSerializer(rfs.Serializer):
    name = rfs.CharField(required=True)
    type_ = rfs.CharField(required=True)
    python_module = rfs.CharField(required=True)
    description = rfs.CharField(required=True)
    disabled = rfs.BooleanField(required=True)
    secrets = rfs.JSONField(required=True)
    config = rfs.JSONField(required=True)

    def validate_secrets(self, secrets):
        errors = {}

        for name, conf in secrets.items():
            if conf.get("required", False):
                secret = get_secret(conf["secret_name"])
                if not secret:
                    errors[name] = f"'{name}': not set"
                elif not isinstance(secret, map_data_type(conf["type"])):
                    errors[
                        name
                    ] = f"'{name}': expected {conf['type']}, got {type(secret)}"

        return errors

    def validate_config(self, config):
        errors = self.validate_secrets(config["secrets"])
        missing_secrets = list(errors.keys())
        tooltip_error_msg = ";".join(errors.values())
        tooltip_error_msg += (
            f", ({len(missing_secrets)} of {len(config['secrets'])} satisfied)"
        )

        verification = {
            "configured": len(missing_secrets) == 0,
            "error_message": tooltip_error_msg,
            "missing_secrets": missing_secrets,
        }

        return verification
