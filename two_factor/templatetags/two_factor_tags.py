from django import template

from two_factor.plugins.registry import registry

register = template.Library()


@register.filter
def as_action(device):
    method = registry.method_from_device(device)
    return method.get_action(device)


@register.filter
def as_verbose_action(device):
    method = registry.method_from_device(device)
    return method.get_verbose_action(device)
