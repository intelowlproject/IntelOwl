from pathlib import Path

from ._util import get_secret

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = get_secret("DEBUG", False) == "True" or get_secret("DEBUG", False) is True

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = Path(__file__).parent.parent.parent
BASE_STATIC_PATH = BASE_DIR / "static"

# test / ci
MOCK_CONNECTIONS = get_secret("MOCK_CONNECTIONS", False) == "True"
STAGE = get_secret("STAGE", "local")
STAGE_PRODUCTION = STAGE == "production"
STAGE_STAGING = STAGE == "staging"
STAGE_LOCAL = STAGE == "local"
STAGE_CI = STAGE == "ci"

# Overridden in test_custom_config
FORCE_SCHEDULE_JOBS = False

VERSION = "4.1.2"
PUBLIC_DEPLOYMENT = get_secret("PUBLIC_DEPLOYMENT", "True") == "True"
PROJECT_LOCATION = "/opt/deploy/intel_owl"

# used for generating links to web client e.g. job results page
WEB_CLIENT_DOMAIN = get_secret("INTELOWL_WEB_CLIENT_DOMAIN")
ORGANIZATION_EMAIL = get_secret("ORGANIZATION_EMAIL")
