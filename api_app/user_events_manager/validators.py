import ipaddress

from django.core.exceptions import ValidationError


def validate_ipv4_network(value):
    try:
        ipaddress.IPv4Network(value)
    except ValueError:
        raise ValidationError("Enter a valid IPv4 network.", code="invalid", params={"value": value})
