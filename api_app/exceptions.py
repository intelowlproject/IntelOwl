# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


class NotRunnableAnalyzer(Exception):
    pass


class AnalyzerConfigurationException(Exception):
    pass


class AnalyzerRunException(Exception):
    pass


class AlreadyFailedJobException(Exception):
    pass


class AnalyzerRunNotImplemented(Exception):
    def __init__(self, analyzer_name):
        self.analyzer_name = analyzer_name

    def __repr__(self):
        return f"run() is not implemented for analyzer {self.analyzer_name}."


class ConnectorConfigurationException(Exception):
    pass


class ConnectorRunException(Exception):
    pass


class ConnectorRunNotImplemented(Exception):
    def __init__(self, connector_name):
        self.connector_name = connector_name

    def __repr__(self):
        return f"run() is not implemented for connector {self.connector_name}."
