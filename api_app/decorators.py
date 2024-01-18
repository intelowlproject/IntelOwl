import functools
import logging

from django.http import HttpResponse

logger = logging.getLogger(__name__)


def deprecated_endpoint(deprecation_date=None, end_of_life_date=None):
    """
    Returns a decorator which informs requester that
    the decorated endpoint has been deprecated.
    """

    def decorator_deprecated(func):
        """Amend the request with information that
        the endpoint has been deprecated and when it will be removed
        """

        @functools.wraps(func)
        def wrapper_deprecated(*args, **kwargs):
            # do something before handling the request, could e.g. issue a django signal
            logger.warning("Deprecated endpoint %s called", func.__name__)

            response: HttpResponse = func(*args, **kwargs)

            # amend the response with deprecation information
            if isinstance(response, HttpResponse):
                response.headers["X-Deprecated"] = ""
                if deprecation_date:
                    response.headers["X-Deprecation-Date"] = deprecation_date
                if end_of_life_date:
                    response.headers["X-End-Of-Life-Date"] = deprecation_date
            return response

        return wrapper_deprecated

    return decorator_deprecated


def prevent_signal_recursion(func):
    @functools.wraps(func)
    def no_recursion(sender, instance=None, **kwargs):
        if not instance:
            return

        if hasattr(instance, "_dirty"):
            return

        func(sender, instance=instance, **kwargs)

        try:
            instance._dirty = True
            instance.save()
        finally:
            del instance._dirty

    return no_recursion
