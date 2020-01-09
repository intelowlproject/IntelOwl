import os

from intel_owl import secrets

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = secrets.get_secret('DJANGO_SECRET')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True if os.environ.get('DEBUG', False) == 'True' else False

LOGIN_URL = "/gui/login"
DJANGO_LOG_DIRECTORY = "/var/log/intel_owl/django"
PROJECT_LOCATION = "/opt/deploy/intel_owl"
MEDIA_ROOT = "/opt/deploy/files_required"
CERTS_DIR = "{}/certs".format(PROJECT_LOCATION)

HTTPS_ENABLED = os.environ.get("HTTPS_ENABLED", "not_enabled")
if HTTPS_ENABLED == "enabled":
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_SECURE = True

ALLOWED_HOSTS = ['*']

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework.authtoken',
    'api_app.apps.ApiAppConfig'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'intel_owl.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'templates'),
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'intel_owl.wsgi.application'

REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ]
}

DB_HOST = secrets.get_secret('DB_HOST')
DB_PORT = secrets.get_secret('DB_PORT')
DB_NAME = os.environ.get('DB_NAME', 'intel_owl_db')
DB_USER = secrets.get_secret('DB_USER')
DB_PASSWORD = secrets.get_secret('DB_PASSWORD')

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': DB_NAME,
        'HOST': DB_HOST,
        'PORT': DB_PORT,
        'USER': DB_USER,
        'PASSWORD': DB_PASSWORD
    },
}


# CELERY STUFF
CELERY_BROKER_URL = secrets.get_secret('CELERY_BROKER_URL')
CELERY_ACCEPT_CONTENT = ['application/json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'Europe/Rome'
CELERY_IMPORTS = ('intel_owl.tasks', )
CELERYD_HIJACK_ROOT_LOGGER = False
# these two are needed to enable priority and correct tasks execution
CELERY_ACKS_LATE = True
CELERYD_PREFETCH_MULTIPLIER = 1
CELERY_TASK_DEFAULT_QUEUE = 'analyzers_queue'

AWS_SQS = True if os.environ.get('AWS_SQS', False) == 'True' else False
if AWS_SQS:
    # this is for AWS SQS support
    CELERY_BROKER_TRANSPORT_OPTIONS = {
        'region': 'eu-central-1',
        'polling_interval': 1,
        'visibility_timeout': 3600,
        'wait_time_seconds': 20
    }

# Auth backends
AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
)

# Password validation

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static/')

STATICFILES_DIRS = (
    os.path.join(BASE_DIR, 'static_intel/'),
)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'stdfmt': {
            'format': '[%(asctime)s - %(levelname)s] %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
    },
    'handlers': {
        'api_app': {
            'level': 'DEBUG' if DEBUG else 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '{}/api_app.log'.format(DJANGO_LOG_DIRECTORY),
            'formatter': 'stdfmt',
            'maxBytes': 20 * 1024 * 1024,
            'backupCount': 6,
        },
        'api_app_error': {
            'level': 'ERROR',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '{}/api_app_errors.log'.format(DJANGO_LOG_DIRECTORY),
            'formatter': 'stdfmt',
            'maxBytes': 20 * 1024 * 1024,
            'backupCount': 6,
        },
    },
    'loggers': {
        'api_app': {
            'handlers': ['api_app', 'api_app_error'],
            'level': 'INFO',
            'propagate': True,
        }
    },
}
