# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""
Minimal stub kept so that historical data migration
0002_0116_analyzer_config_talosreputation can still import the module
path during full_clean().  The analyzer itself is removed; migration
0176_remove_talos_reputation deletes the DB rows.
"""

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.exceptions import AnalyzerRunException


class Talos(ObservableAnalyzer):
    def run(self):
        raise AnalyzerRunException("TalosReputation has been deprecated and removed.")

    @classmethod
    def update(cls):
        return False
