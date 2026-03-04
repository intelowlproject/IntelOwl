# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


class NotRunnableAnalyzer(Exception):
    """Exception raised when an analyzer cannot be run."""
    pass


class AnalyzerRunException(Exception):
    """Exception raised when an analyzer run fails."""
    pass


class AnalyzerConfigurationException(Exception):
    """Exception raised when analyzer configuration is invalid."""
    pass
