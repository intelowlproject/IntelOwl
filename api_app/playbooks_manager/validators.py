from api_app.validators import validate_schema


def validate_runtime_configuration_playbook(value):
    schema = {
        "type": "object",
        "title": "RuntimeConfig",
        "properties": {
            "analyzers": {
                "type": "object",
                "patternProperties": {
                    "^[A-Za-z][A-Za-z0-9_]*$": {"type": "object"},
                },
            },
            "connectors": {
                "type": "object",
                "patternProperties": {
                    "^[A-Za-z][A-Za-z0-9_]*$": {"type": "object"},
                },
            },
        },
        "additionalProperties": False,
        "required": ["analyzers", "connectors"],
    }
    return validate_schema(value, schema)
