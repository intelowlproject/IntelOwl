# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

RADIUS_SERVER = "localhost"
RADIUS_PORT = 1812
RADIUS_SECRET = "S3kr3T"

RADIUS_REMOTE_ROLES = True

# https://github.com/robgolding/django-radius#customised-functionality
# The get_server method of the backend class is used to determine
# which RADIUS server to authenticate against.
# It can be customised to achieve things like multiple RADIUS servers (realms).
# Set GET_SERVER_CUSTOMISED to True to use this functionality.
GET_SERVER_CUSTOMISED = False


def custom_get_server(self, realm):
    # /* Custom realm logic here */
    pass


# https://github.com/robgolding/django-radius#additional-attributes
# RADIUS_ATTRIBUTES = {}

# https://github.com/robgolding/django-radius#group-mapping
# RADIUS_CLASS_APP_PREFIX = 'some_project_name'
