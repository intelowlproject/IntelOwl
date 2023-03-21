# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from apkid.apkid import Options, Scanner

from api_app.analyzers_manager.classes import FileAnalyzer


class APKiD(FileAnalyzer):
    def set_params(self, params):
        self.timeout = params.get("timeout", 20)

    def run(self):
        options = Options(
            timeout=self.timeout,
            json=True,
        )

        rules = options.rules_manager.load()
        scanner = Scanner(rules, options)
        binary = self.read_file_bytes()
        results = scanner.scan_file_obj(binary)
        print(results)

        return results
