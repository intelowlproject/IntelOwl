import logging

from rest_framework.exceptions import ValidationError
from rest_framework.request import Request

from certego_saas.ext.exceptions import custom_exception_handler

logger = logging.getLogger(__name__)


def logging_exception_handler(exc, context):
    if isinstance(exc, ValidationError):
        request: Request = context["request"]
        logger.info(
            f"Validation error: {str(exc)} "
            f"raised by user:{request.user}"
            f" with content:{request.data}"
        )
        logger.info(context)
    return custom_exception_handler(exc, context)
