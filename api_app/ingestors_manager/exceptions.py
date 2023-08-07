# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


class NotRunnableIngestor(Exception):
    pass


class IngestorConfigurationException(Exception):
    pass


class IngestorRunException(Exception):
    pass
