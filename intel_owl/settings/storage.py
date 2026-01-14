# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import os
import tempfile

from django.core.files.storage import FileSystemStorage
from filelock import FileLock, Timeout

from intel_owl import secrets

from ._util import get_secret
from .commons import BASE_STATIC_PATH, MEDIA_ROOT

logger = logging.getLogger(__name__)

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
            """
            Retrieve a file from S3 storage, downloading it locally if necessary.
            
            This method implements file locking to prevent race conditions when
            multiple analyzers attempt to download the same file concurrently.
            Uses a double-check pattern with file locking to ensure atomic operations.
            
            Args:
                file: The file object to retrieve
                analyzer: The analyzer name (used for directory organization)
            
            Returns:
                str: The local file path
            
            Raises:
                FileNotFoundError: If the file doesn't exist in S3
                RuntimeError: If file download fails after waiting for lock
                Timeout: If lock acquisition times out (default 5 minutes)
            """
            path_dir = os.path.join(MEDIA_ROOT, analyzer)
            name = file.name
            _path = os.path.join(path_dir, name)
            lock_path = f"{_path}.lock"
            
            # Fast path: file already exists
            if os.path.exists(_path):
                return _path
            
            # Ensure directory exists (safe to call multiple times)
            os.makedirs(path_dir, exist_ok=True)
            
            # Use file lock to prevent race conditions
            lock = FileLock(lock_path, timeout=300)  # 5 minute timeout
            try:
                with lock:
                    # Double-check pattern: verify file still doesn't exist after acquiring lock
                    if not os.path.exists(_path):
                        # Verify file exists in S3 before attempting download
                        if not self.exists(name):
                            raise FileNotFoundError(
                                f"File '{name}' does not exist in S3 bucket "
                                f"'{self.bucket_name if hasattr(self, 'bucket_name') else 'unknown'}'"
                            )
                        
                        # Download to temporary file first for atomic write
                        temp_path = f"{_path}.tmp"
                        try:
                            logger.info(
                                f"Downloading file '{name}' from S3 for analyzer '{analyzer}'"
                            )
                            with self.open(name) as s3_file_object:
                                content = s3_file_object.read()
                                with open(temp_path, "wb") as temp_file:
                                    temp_file.write(content)
                            
                            # Atomic rename operation (POSIX-compliant)
                            os.rename(temp_path, _path)
                            logger.info(
                                f"Successfully downloaded file '{name}' to '{_path}'"
                            )
                        except Exception as e:
                            # Cleanup temporary file on failure
                            if os.path.exists(temp_path):
                                try:
                                    os.remove(temp_path)
                                except OSError:
                                    pass
                            logger.error(
                                f"Failed to download file '{name}' from S3: {e}",
                                exc_info=True,
                            )
                            raise
                    else:
                        # Another process downloaded the file while we were waiting
                        logger.debug(
                            f"File '{_path}' was downloaded by another process, "
                            "using existing file"
                        )
            except Timeout:
                logger.error(
                    f"Timeout waiting for file lock on '{lock_path}'. "
                    "Another process may be stuck downloading the file."
                )
                raise
            except Exception as e:
                logger.error(
                    f"Unexpected error while retrieving file '{name}': {e}",
                    exc_info=True,
                )
                raise
            
            return _path

    DEFAULT_FILE_STORAGE = "intel_owl.settings.S3Boto3StorageWrapper"
    AWS_STORAGE_BUCKET_NAME = secrets.get_secret("AWS_STORAGE_BUCKET_NAME")
