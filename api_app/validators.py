# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import jsonschema
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator

from api_app.choices import ParamTypes

plugin_name_validator = RegexValidator(r"^\w+$", "Your name should match the [A-Za-z0-9_] characters")


def validate_schema(value, schema):
    try:
        return jsonschema.validate(value, schema=schema)
    except jsonschema.exceptions.ValidationError as e:
        raise ValidationError(e.message)


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
                    "type": {"enum": ParamTypes.values},
                    "default": {"type": ["string", "boolean", "array", "number", "object"]},
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
                    "type": {"enum": ParamTypes.values},
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


def validate_runtime_configuration(value):
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
            "pivots": {
                "type": "object",
                "patternProperties": {
                    "^[A-Za-z][A-Za-z0-9_]*$": {"type": "object"},
                },
            },
            "visualizers": {
                "type": "object",
                "patternProperties": {
                    "^[A-Za-z][A-Za-z0-9_]*$": {"type": "object"},
                },
            },
        },
        "additionalProperties": False,
        "required": ["analyzers", "connectors", "visualizers"],
    }
    return validate_schema(value, schema)
