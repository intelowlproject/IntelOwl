# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from api_app.analyzers_manager import classes


class AbuseWHOIS(classes.ObservableAnalyzer):

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        """Run the analyzer"""
        return None

    @classmethod
    def _monkeypatch(cls):
        patches = []
        return super()._monkeypatch(patches=patches)
