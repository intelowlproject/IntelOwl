import jsonschema
from django.core.exceptions import ValidationError

from intel_owl.consts import PARAM_DATATYPE_CHOICES


def validate_schema(value, schema):
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
    return validate_schema(value, schema)


def validate_secrets(value):
    schema = {
        "type": "object",
        "title": "Secret",
        "patternProperties": {
            "^[A-Za-z][A-Za-z0-9_]*$": {
                "type": "object",
                "properties": {
                    "description": {"type": "string"},
                    "required": {"type": "boolean"},
                    "type": {"enum": list(PARAM_DATATYPE_CHOICES.keys())},
                    "default": {
                        "type": ["string", "boolean", "array", "number", "object"]
                    },
                },
                "additionalProperties": False,
                "required": ["description", "required", "type"],
            },
        },
        "additionalProperties": False,
    }
    return validate_schema(value, schema)


def validate_params(value):
    schema = {
        "type": "object",
        "title": "Param",
        "patternProperties": {
            "^[A-Za-z][A-Za-z0-9_]*$": {
                "type": "object",
                "properties": {
                    "type": {"enum": list(PARAM_DATATYPE_CHOICES.keys())},
                    "description": {"type": "string"},
                    "default": {},
                },
                "additionalProperties": False,
                "required": ["type", "description", "default"],
            },
        },
        "additionalProperties": False,
    }
    return validate_schema(value, schema)
