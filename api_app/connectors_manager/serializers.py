from rest_framework import serializers

from intel_owl import secrets as secrets_store


DATA_TYPE_MAPPING = {
    "number": (
        int,
        float,
    ),
    "string": str,
    "bool": bool,
}


class ConnectorConfigSerializer(serializers.Serializer):
    """
    serializer for connectors from connector_config.json.
    """

    disabled = serializers.BooleanField()
    description = serializers.CharField(max_length=512)
    python_module = serializers.CharField(max_length=128)
    config = serializers.JSONField()
    secrets = serializers.JSONField()
    verification = serializers.SerializerMethodField()

    def check_secrets(self, secrets):
        exceptions = {}
        for key_name, secret_dict in secrets.items():
            if "required" in secret_dict and secret_dict["required"]:
                # check if set and correct data type
                secret_val = secrets_store.get_secret(secret_dict["secret_name"])
                if not secret_val:
                    exceptions[key_name] = f"'{key_name}': not set"
                elif secret_val and not isinstance(
                    secret_val, DATA_TYPE_MAPPING[secret_dict["type"]]
                ):
                    exceptions[key_name] = "'%s': expected %s got %s" % (
                        key_name,
                        secret_dict["type"],
                        type(secret_val),
                    )
        return exceptions

    def get_verification(self, raw_instance):
        # raw instance because input is json and not django model object
        exceptions = self.check_secrets(raw_instance["secrets"])
        missing_secrets = list(exceptions.keys())
        final_err_msg = ";".join(exceptions.values())
        final_err_msg += "; (%d of %d satisfied)" % (
            len(missing_secrets),
            len(raw_instance["secrets"].keys()),
        )

        return {
            "configured": len(missing_secrets) == 0,
            "error_message": final_err_msg,
            "missing_secrets": missing_secrets,
        }
