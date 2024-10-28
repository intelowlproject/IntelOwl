import androguard
import androguard.core
import androguard.core.bytecodes
import androguard.core.bytecodes.apk

from api_app.analyzers_manager.classes import FileAnalyzer


class AndroguardAnalyzer(FileAnalyzer):

    def update(self) -> bool:
        pass

    def run(self):

        binary = self.read_file_bytes()
        apk = androguard.core.bytecodes.apk.APK(binary, raw=True)
        results = {
            "app_name": apk.get_app_name(),
            "permissions": apk.get_permissions(),
            "activities": apk.get_activities(),
            "requested_third_party_permissions": apk.get_requested_third_party_permissions(),
            "providers": apk.get_providers(),
            "features": apk.get_features(),
            "receivers": apk.get_receivers(),
            "services": apk.get_services(),
            "is_valid_apk": apk.is_valid_APK(),
            "min_sdk_version": apk.get_min_sdk_version(),
            "max_sdk_version": apk.get_max_sdk_version(),
            "target_sdk_version": apk.get_target_sdk_version(),
            "android_version_code": apk.get_androidversion_code(),
            "android_version_name": apk.get_androidversion_name(),
        }

        return results
