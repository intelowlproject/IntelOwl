# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import os

from django.core.files.storage import FileSystemStorage

from intel_owl import secrets

from ._util import get_secret
from .commons import BASE_STATIC_PATH, MEDIA_ROOT

# Static Files (CSS, JavaScript, Images)
STATIC_URL = "/static/"
STATIC_ROOT = str(BASE_STATIC_PATH)
STATICFILES_DIRS = [
    ("reactapp", "/var/www/reactapp"),
]

NFS = get_secret("NFS", "False") == "True"
LOCAL_STORAGE = get_secret("LOCAL_STORAGE", "True") == "True"
# Storage settings
if LOCAL_STORAGE:

    class FileSystemStorageWrapper(FileSystemStorage):
        @staticmethod
        def retrieve(file, analyzer):
            # we have one single sample for every analyzer
            return file.path

    DEFAULT_FILE_STORAGE = "intel_owl.settings.FileSystemStorageWrapper"
else:
    from storages.backends.s3boto3 import S3Boto3Storage

    class S3Boto3StorageWrapper(S3Boto3Storage):
        # Shared cache directory where files are downloaded once and
        # reused by every analyzer that needs them.
        _CACHE_DIR = os.path.join(MEDIA_ROOT, "_s3_cache")

        def retrieve(self, file, analyzer):
            name = file.name
            _path = os.path.join(self._CACHE_DIR, name)
            if not os.path.exists(_path):
                os.makedirs(os.path.dirname(_path), exist_ok=True)
                if not self.exists(name):
                    raise AssertionError
                # Write to a temp file first, then rename for atomicity.
                # This prevents a concurrent worker from reading a half-written file.
                tmp_path = _path + ".tmp"
                with self.open(name) as s3_file_object:
                    content = s3_file_object.read()
                    with open(tmp_path, "wb") as local_file_object:
                        local_file_object.write(content)
                # atomic on the same filesystem
                os.replace(tmp_path, _path)
            return _path

    DEFAULT_FILE_STORAGE = "intel_owl.settings.S3Boto3StorageWrapper"
    AWS_STORAGE_BUCKET_NAME = secrets.get_secret("AWS_STORAGE_BUCKET_NAME")
