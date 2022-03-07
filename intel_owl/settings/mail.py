# todo: there is no actual implementation of mail senders
# force in-memory backend for tests/internal deployments
# see: https://docs.djangoproject.com/en/2.1/topics/email/#in-memory-backend
# see: https://docs.djangoproject.com/en/2.1/topics/testing/tools/#topics-testing-email
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
