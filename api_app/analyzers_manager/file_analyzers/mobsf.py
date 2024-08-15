from mobsfscan.mobsfscan import MobSFScan

from api_app.analyzers_manager.classes import FileAnalyzer


class Mobsf(FileAnalyzer):
    def update(self):
        pass

    def run(self):
        scanner = MobSFScan([self.filepath], json=True)
        result = scanner.scan()
        return result
