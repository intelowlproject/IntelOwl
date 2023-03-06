from api_app.models import Position
from api_app.validators import validate_schema


def validate_report(value):
    schema = {
        "type": "object",
        "title": "Report",
        "patternProperties": {
            "^[A-Za-z][A-Za-z0-9_]*$": {
                "type": "object",
                "properties": {
                    "value": {},
                    "position": {"enum": list(Position.values)},
                    "priority": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 10,
                    },
                },
                "additionalProperties": False,
            }
        },
        "additionalProperties": False,
    }
    return validate_schema(value, schema)
