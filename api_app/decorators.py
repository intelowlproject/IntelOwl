import functools
import logging

from django.http import HttpResponse

logger = logging.getLogger(__name__)


class classproperty(property):
    """Read-only class property descriptor.
    Replacement for deprecated @classmethod + @property.
    """

    def __get__(self, obj, owner=None):
        return self.fget(owner if owner is not None else type(obj))


class abstractclassproperty(property):
    """Abstract read-only class property.
    Enforced when the class uses ABCMeta metaclass.
    """

    __isabstractmethod__ = True

    def __get__(self, obj, owner=None):
        return self.fget(owner if owner is not None else type(obj))


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
            """
            Wrapper function to log a warning and amend the response with
            deprecation headers.
            """
            # do something before handling the request, could e.g. issue a django signal
            logger.warning("Deprecated endpoint %s called", func.__name__)

            response: HttpResponse = func(*args, **kwargs)

            # amend the response with deprecation information
            if isinstance(response, HttpResponse):
                response.headers["X-Deprecated"] = ""
                if deprecation_date:
                    response.headers["X-Deprecation-Date"] = deprecation_date
                if end_of_life_date:
                    response.headers["X-End-Of-Life-Date"] = end_of_life_date
            return response

        return wrapper_deprecated

    return decorator_deprecated


def prevent_signal_recursion(func):
    """
    Decorator to prevent recursion issues when saving Django model instances.
    It ensures that the decorated function does not cause a recursion loop
    during model save operations.

    Args:
        func (function): The function to be decorated.

    Returns:
        function: The wrapper function that prevents recursion.
    """

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
