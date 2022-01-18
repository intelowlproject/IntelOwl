# Database Conf

from intel_owl import secrets

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

PG_DB = secrets.get_secret("DB_NAME", "intel_owl_db")
PG_HOST = secrets.get_secret("DB_HOST")
PG_PORT = secrets.get_secret("DB_PORT")
PG_USER = secrets.get_secret("DB_USER")
PG_PASSWORD = secrets.get_secret("DB_PASSWORD")
PG_SSL = secrets.get_secret("POSTGRES_SSL", "True") == "True"


DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": PG_DB,
        "HOST": PG_HOST,
        "PORT": PG_PORT,
        "USER": PG_USER,
        "PASSWORD": PG_PASSWORD,
        # "OPTIONS": {"sslmode": "require"} if PG_SSL else {},
        "TIMEOUT": 180,
    },
}
