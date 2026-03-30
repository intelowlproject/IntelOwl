# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from functools import wraps

import requests
from django.conf import settings


def _get_timeout(kwargs):
    """
    Internal helper to extract timeout from kwargs or use the default.
    """
    return kwargs.pop("timeout", settings.HTTP_TIMEOUT)


def get(url, params=None, **kwargs):
    """
    Sends a GET request with a default timeout.
    """
    timeout = _get_timeout(kwargs)
    return requests.get(url, params=params, timeout=timeout, **kwargs)


def post(url, data=None, json=None, **kwargs):
    """
    Sends a POST request with a default timeout.
    """
    timeout = _get_timeout(kwargs)
    return requests.post(url, data=data, json=json, timeout=timeout, **kwargs)


def put(url, data=None, **kwargs):
    """
    Sends a PUT request with a default timeout.
    """
    timeout = _get_timeout(kwargs)
    return requests.put(url, data=data, timeout=timeout, **kwargs)


def patch(url, data=None, **kwargs):
    """
    Sends a PATCH request with a default timeout.
    """
    timeout = _get_timeout(kwargs)
    return requests.patch(url, data=data, timeout=timeout, **kwargs)


def delete(url, **kwargs):
    """
    Sends a DELETE request with a default timeout.
    """
    timeout = _get_timeout(kwargs)
    return requests.delete(url, timeout=timeout, **kwargs)


def head(url, **kwargs):
    """
    Sends a HEAD request with a default timeout.
    """
    timeout = _get_timeout(kwargs)
    return requests.head(url, timeout=timeout, **kwargs)


def request(method, url, **kwargs):
    """
    Constructs and sends a Request with a default timeout.
    """
    timeout = _get_timeout(kwargs)
    return requests.request(method, url, timeout=timeout, **kwargs)


class Session(requests.Session):
    """
    A wrapper around requests.Session that automatically applies
    the default HTTP_TIMEOUT to all requests.
    """

    def request(self, method, url, **kwargs):
        if "timeout" not in kwargs:
            kwargs["timeout"] = settings.HTTP_TIMEOUT
        return super().request(method, url, **kwargs)


def verify_timeout(func):
    """
    Decorator that ensures the decorated function (which should call a requests method)
    is called with a 'timeout' argument. If not, it injects the default.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        if "timeout" not in kwargs:
            kwargs["timeout"] = settings.HTTP_TIMEOUT
        return func(*args, **kwargs)

    return wrapper
