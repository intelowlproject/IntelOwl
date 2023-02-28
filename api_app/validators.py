import jsonschema
from django.core.exceptions import ValidationError

from intel_owl.consts import PARAM_DATATYPE_CHOICES


def _validate(value, schema):
    try:
        return jsonschema.validate(value, schema=schema)
    except jsonschema.exceptions.ValidationError as e:
        raise ValidationError(e.message)


def validate_config(value):
    schema = {
        "type": "object",
        "title": "Config",
        "properties": {
            "soft_time_limit": {
                "title": "Execution soft time limit",
                "type": "integer",
            },
            "queue": {
                "title": "Celery queue",
                "type": "string",
            },
        },
        "required": ["soft_time_limit", "queue"],
        "additionalProperties": False,
    }
    return _validate(value, schema)


def validate_secrets(value):
    schema = {
        "type": "object",
        "title": "Secret",
        "patternProperties": {
            "^[A-Za-z_][A-Za-z0-9_]*$": {
                "type": "object",
                "properties": {
                    "env_var_key": {"type": "string"},
                    "description": {"type": "string"},
                    "required": {"type": "boolean"},
                    "type": {"enum": list(PARAM_DATATYPE_CHOICES.keys())},
                    "default": {
                        "type": ["string", "boolean", "array", "number", "object"]
                    },
                },
                "additionalProperties": False,
                "required": ["env_var_key", "description", "required", "type"],
            },
        },
    }
    return _validate(value, schema)


def validate_params(value):
    schema = {
        "type": "object",
        "title": "Param",
        "patternProperties": {
            "^[A-Za-z_][A-Za-z0-9_]*$": {
                "type": "object",
                "properties": {
                    "value": {
                        "type": ["string", "boolean", "array", "number", "object"]
                    },
                    "type": {"enum": list(PARAM_DATATYPE_CHOICES.keys())},
                    "description": {"type": "string"},
                },
                "additionalProperties": False,
                "required": ["type", "description", "value"],
            },
        },
    }
    return _validate(value, schema)


def validate_runtime_configuration_playbook(value):
    schema = {
        "type": "object",
        "title": "RuntimeConfig",
        "properties": {
            "analyzers": {
                "type": "array",
                "items": {
                    "type": "object"
                }
            },
            "connectors": {
                "type": "array",
                "items": {
                    "type": "object"
                }
            }

        },
        "required": ["analyzers", "connectors"]
    }
    return _validate(value, schema)