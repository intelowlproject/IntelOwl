from ._util import get_secret
from .commons import AWS_REGION, STAGE_CI, STAGE_LOCAL

DEFAULT_FROM_EMAIL = get_secret("DEFAULT_FROM_EMAIL")
DEFAULT_EMAIL = get_secret("DEFAULT_EMAIL")

if STAGE_LOCAL:
    # The console backend writes the emails that would be sent to the standard output
    # https://docs.djangoproject.com/en/4.1/topics/email/#console-backend
    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
elif STAGE_CI:
    # force in-memory backend for tests/internal deployments
    # https://docs.djangoproject.com/en/2.1/topics/email/#in-memory-backend
    # https://docs.djangoproject.com/en/2.1/topics/testing/tools/#topics-testing-email
    EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
else:
    # Use amazon SES via django-ses
    # see: https://github.com/django-ses/django-ses
    EMAIL_BACKEND = "django_ses.SESBackend"
    AWS_SES_REGION_NAME = AWS_REGION
    AWS_SES_REGION_ENDPOINT = f"email.{AWS_SES_REGION_NAME}.amazonaws.com"
