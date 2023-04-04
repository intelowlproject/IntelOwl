# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import sys
from time import time
from unittest.runner import TextTestResult, TextTestRunner

from django.test.runner import DiscoverRunner


class TimedTextTestResult(TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.clocks = {}

    def startTest(self, test):
        self.clocks[test] = time()
        super(TextTestResult, self).startTest(test)
        self.stream.write(self.getDescription(test))
        self.stream.write(" ... ")

    def addSuccess(self, test):
        super(TextTestResult, self).addSuccess(test)
        self.stream.writeln("ok-dokey (%.6fs)" % (time() - self.clocks[test]))
        self.stream.flush()


class TimedTextTestRunner(TextTestRunner):
    resultclass = TimedTextTestResult
    stream = sys.stdout


class MyTestRunner(DiscoverRunner):
    test_runner = TimedTextTestRunner
