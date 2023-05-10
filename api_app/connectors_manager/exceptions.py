# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


class NotRunnableConnector(Exception):
    pass


class ConnectorConfigurationException(Exception):
    pass


class ConnectorRunException(Exception):
    pass
