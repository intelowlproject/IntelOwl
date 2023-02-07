from pathlib import Path

from ._util import get_secret

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = get_secret("DEBUG", False) == "True" or get_secret("DEBUG", False) is True

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = Path(__file__).parent.parent.parent.parent
PROJECT_LOCATION = BASE_DIR / "intel_owl"

BASE_STATIC_PATH = PROJECT_LOCATION / "static"

# test / ci
MOCK_CONNECTIONS = get_secret("MOCK_CONNECTIONS", False) == "True"
STAGE = get_secret("STAGE", "local")
STAGE_PRODUCTION = STAGE == "production"
STAGE_STAGING = STAGE == "staging"
STAGE_LOCAL = STAGE == "local"
STAGE_CI = STAGE == "ci"

# Overridden in test_custom_config
FORCE_SCHEDULE_JOBS = True

VERSION = get_secret("REACT_APP_INTELOWL_VERSION", "").replace("v", "")
PUBLIC_DEPLOYMENT = get_secret("PUBLIC_DEPLOYMENT", "True") == "True"

# used for generating links to web client e.g. job results page
WEB_CLIENT_DOMAIN = get_secret("INTELOWL_WEB_CLIENT_DOMAIN")

AWS_REGION = get_secret("AWS_REGION")

BASE_CONNECTOR_PYTHON_PATH = get_secret(
    "BASE_CONNECTOR_PYTHON_PATH", "api_app.connectors_manager.connectors"
)
BASE_ANALYZER_OBSERVABLE_PYTHON_PATH = get_secret(
    "", "api_app.analyzers_manager.observable_analyzers"
)
BASE_ANALYZER_FILE_PYTHON_PATH = get_secret(
    "", "api_app.analyzers_manager.file_analyzers"
)
