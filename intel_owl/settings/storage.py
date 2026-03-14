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
        def retrieve(self, file, analyzer):
            # Download the file once into MEDIA_ROOT/<filename> and share the
            # cached copy across all analyzers that need the same sample.
            name = file.name
            _path = os.path.join(MEDIA_ROOT, name)
            if not os.path.exists(_path):
                os.makedirs(MEDIA_ROOT, exist_ok=True)
                if not self.exists(name):
                    raise AssertionError
                with self.open(name) as s3_file_object:
                    content = s3_file_object.read()
                    s3_file_object.seek(0)
                    with open(_path, "wb") as local_file_object:
                        local_file_object.write(content)
            return _path

    DEFAULT_FILE_STORAGE = "intel_owl.settings.S3Boto3StorageWrapper"
    AWS_STORAGE_BUCKET_NAME = secrets.get_secret("AWS_STORAGE_BUCKET_NAME")
