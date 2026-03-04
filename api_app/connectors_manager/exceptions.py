# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


class NotRunnableConnector(Exception):
    """Exception raised when a connector cannot be run."""
    pass


class ConnectorConfigurationException(Exception):
    """Exception raised when connector configuration is invalid."""
    pass


class ConnectorRunException(Exception):
    """Exception raised when a connector run fails."""
    pass
