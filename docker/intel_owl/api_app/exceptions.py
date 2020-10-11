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
