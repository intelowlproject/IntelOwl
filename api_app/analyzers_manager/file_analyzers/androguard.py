import androguard
import androguard.misc

from api_app.analyzers_manager.classes import FileAnalyzer


class AndroguardAnalyzer(FileAnalyzer):
    def run(self):

        results = {
            "app_name": "",
            "permissions": [],
            "activities": [],
            "requested_third_party_permissions": [],
            "providers": [],
            "features": [],
        }

        binary = self.read_file_bytes()

        apk = androguard.misc.APK(binary, raw=True)

        results["app_name"] = apk.get_app_name()
        results["permissions"] = apk.get_permissions()
        results["activities"] = apk.get_activities()
        results["requested_third_party_permissions"] = (
            apk.get_requested_third_party_permissions()
        )
        results["providers"] = apk.get_providers()
        results["features"] = apk.get_features()

        return results
