from androguard.misc import get_default_session

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.models import MimeTypes


class AndroguardAnalyzer(FileAnalyzer):
    def update(self) -> bool:
        pass

    def run(self):
        self.read_file_bytes()
        session = get_default_session()

        if self._job.analyzable.mimetype == MimeTypes.DEX:
            session.addDEX(self._job.analyzable.name, self.read_file_bytes())
            results = {}
        else:
            _, apk = session.addAPK(self._job.analyzable.name, self.read_file_bytes())
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
