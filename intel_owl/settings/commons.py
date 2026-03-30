# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import tomllib
from pathlib import Path, PosixPath

from ._util import get_secret

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = get_secret("DEBUG", False) == "True" or get_secret("DEBUG", False) is True

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = Path(__file__).parent.parent.parent
PROJECT_LOCATION = BASE_DIR
BASE_STATIC_PATH = PROJECT_LOCATION / "intel_owl" / "static"
MEDIA_ROOT = BASE_DIR / "files_required"
CONFIG_ROOT = PROJECT_LOCATION / "intel_owl" / "configuration"
BLINT_REPORTS_PATH = MEDIA_ROOT / "blint"
YARA_RULES_PATH = MEDIA_ROOT / "yara"  # path for manual yara rules

LOG_DIR = Path("/") / "var" / "log" / "intel_owl"
# test / ci
MOCK_CONNECTIONS = get_secret("MOCK_CONNECTIONS", False) == "True"
STAGE = get_secret("STAGE", "local")
STAGE_PRODUCTION = STAGE == "production"
STAGE_STAGING = STAGE == "staging"
STAGE_LOCAL = STAGE == "local"
STAGE_CI = STAGE == "ci"

# Overridden in test_custom_config
FORCE_SCHEDULE_JOBS = True

# VERSION is read from pyproject.toml
try:
    with open(PROJECT_LOCATION / "pyproject.toml", "rb") as f:
        VERSION = tomllib.load(f)["project"]["version"]
except (FileNotFoundError, KeyError, tomllib.TOMLDecodeError):
    VERSION = get_secret("REACT_APP_INTELOWL_VERSION", "").replace("v", "")

PUBLIC_DEPLOYMENT = get_secret("PUBLIC_DEPLOYMENT", "True") == "True"

# used for generating links to web client e.g. job results page
WEB_CLIENT_DOMAIN = get_secret("INTELOWL_WEB_CLIENT_DOMAIN")

BASE_ANALYZER_OBSERVABLE_PYTHON_PATH = PosixPath(
    get_secret(
        "BASE_ANALYZER_OBSERVABLE_PYTHON_PATH",
        "api_app.analyzers_manager.observable_analyzers",
    )
)
BASE_ANALYZER_FILE_PYTHON_PATH = PosixPath(
    get_secret("BASE_ANALYZER_FILE_PYTHON_PATH", "api_app.analyzers_manager.file_analyzers")
)
BASE_ENGINE_MODULES_PYTHON_PATH = PosixPath(
    get_secret("BASE_ENGINE_MODULES_PYTHON_PATH", "api_app.engines_manager.engines")
)

REPO_DOWNLOADER_ENABLED = get_secret("REPO_DOWNLOADER_ENABLED", "True") == "True"
GIT_KEY_PATH = MEDIA_ROOT / "my_gitpython_key"
GIT_SSH_SCRIPT_PATH = PROJECT_LOCATION / "api_app" / "analyzers_manager" / "ssh_gitpython.sh"
