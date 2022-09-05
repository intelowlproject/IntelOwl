# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


class UnsupportedFileException(Exception):
    pass


class UnsupportedObservableException(Exception):
    pass


class NotRunnableAnalyzer(Exception):
    pass


class NotRunnableConnector(Exception):
    pass


class NotRunnablePlaybook(Exception):
    pass


class AnalyzerConfigurationException(Exception):
    pass


class AnalyzerRunException(Exception):
    pass


class AlreadyFailedJobException(Exception):
    pass


class ConnectorConfigurationException(Exception):
    pass


class ConnectorRunException(Exception):
    pass


class PlaybookConfigurationException(Exception):
    pass


class PlaybookRunException(Exception):
    pass
