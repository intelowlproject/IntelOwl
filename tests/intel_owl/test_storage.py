# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, Mock, patch

from django.test import TestCase, override_settings

from intel_owl.settings.storage import S3Boto3StorageWrapper
from tests import CustomTestCase


class MockFile:
    """Mock file object for testing"""

    def __init__(self, name, content=b"test content"):
        self.name = name
        self.content = content


@override_settings(LOCAL_STORAGE=False)
class S3StorageRetrieveTestCase(CustomTestCase):
    """Test cases for S3Boto3StorageWrapper.retrieve() race condition fix"""

    def setUp(self):
        """Set up test fixtures"""
        super().setUp()
        # Create temporary directory for MEDIA_ROOT
        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: self._cleanup_temp_dir(self.temp_dir))

        # Mock MEDIA_ROOT
        with patch("intel_owl.settings.storage.MEDIA_ROOT", self.temp_dir):
            self.storage = S3Boto3StorageWrapper()
            self.storage.bucket_name = "test-bucket"

    def _cleanup_temp_dir(self, temp_dir):
        """Clean up temporary directory"""
        import shutil

        try:
            shutil.rmtree(temp_dir)
        except OSError:
            pass

    @patch.object(S3Boto3StorageWrapper, "exists")
    @patch.object(S3Boto3StorageWrapper, "open")
    def test_single_retrieve(self, mock_open, mock_exists):
        """Test that a single retrieve operation works correctly"""
        file = MockFile("test.exe", b"test content")
        mock_exists.return_value = True

        # Mock S3 file object
        mock_s3_file = Mock()
        mock_s3_file.read.return_value = b"test content"
        mock_s3_file.__enter__ = Mock(return_value=mock_s3_file)
        mock_s3_file.__exit__ = Mock(return_value=False)
        mock_open.return_value = mock_s3_file

        with patch("intel_owl.settings.storage.MEDIA_ROOT", self.temp_dir):
            path = self.storage.retrieve(file, "test_analyzer")

        # Verify file was created
        self.assertTrue(os.path.exists(path))
        with open(path, "rb") as f:
            self.assertEqual(f.read(), b"test content")

        # Verify S3 was called once
        mock_exists.assert_called_once_with("test.exe")
        mock_open.assert_called_once_with("test.exe")

    @patch.object(S3Boto3StorageWrapper, "exists")
    @patch.object(S3Boto3StorageWrapper, "open")
    def test_concurrent_retrieve_same_file(self, mock_open, mock_exists):
        """Test that multiple concurrent retrievals don't cause redundant downloads"""
        file = MockFile("test.exe", b"test content")
        mock_exists.return_value = True

        # Mock S3 file object
        mock_s3_file = Mock()
        mock_s3_file.read.return_value = b"test content"
        mock_s3_file.__enter__ = Mock(return_value=mock_s3_file)
        mock_s3_file.__exit__ = Mock(return_value=False)
        mock_open.return_value = mock_s3_file

        with patch("intel_owl.settings.storage.MEDIA_ROOT", self.temp_dir):
            # Simulate 5 concurrent retrievals (typical job scenario)
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [
                    executor.submit(
                        self.storage.retrieve, file, f"analyzer_{i}"
                    )
                    for i in range(5)
                ]
                paths = [f.result() for f in futures]

        # Verify all paths are the same (same file)
        self.assertEqual(len(set(paths)), 1)

        # Verify file exists and has correct content
        path = paths[0]
        self.assertTrue(os.path.exists(path))
        with open(path, "rb") as f:
            self.assertEqual(f.read(), b"test content")

        # Verify S3 API was called only once (not 5 times)
        # Note: exists() may be called multiple times, but open() should be called once
        self.assertEqual(mock_open.call_count, 1)

    @patch.object(S3Boto3StorageWrapper, "exists")
    @patch.object(S3Boto3StorageWrapper, "open")
    def test_no_file_corruption_on_concurrent_write(self, mock_open, mock_exists):
        """Test that concurrent writes don't corrupt file content"""
        large_content = b"test content" * 10000  # Larger file to increase race window
        file = MockFile("test.exe", large_content)
        mock_exists.return_value = True

        # Mock S3 file object
        mock_s3_file = Mock()
        mock_s3_file.read.return_value = large_content
        mock_s3_file.__enter__ = Mock(return_value=mock_s3_file)
        mock_s3_file.__exit__ = Mock(return_value=False)
        mock_open.return_value = mock_s3_file

        with patch("intel_owl.settings.storage.MEDIA_ROOT", self.temp_dir):
            # Concurrent writes from 10 analyzers
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [
                    executor.submit(
                        self.storage.retrieve, file, f"analyzer_{i}"
                    )
                    for i in range(10)
                ]
                paths = [f.result() for f in futures]

        # Verify file integrity for all returned paths
        for path in paths:
            self.assertTrue(os.path.exists(path))
            with open(path, "rb") as f:
                content = f.read()
                self.assertEqual(
                    content,
                    large_content,
                    f"File {path} is corrupted or incomplete",
                )
                self.assertEqual(len(content), len(large_content))

    @patch.object(S3Boto3StorageWrapper, "exists")
    @patch.object(S3Boto3StorageWrapper, "open")
    def test_file_already_exists_returns_immediately(self, mock_open, mock_exists):
        """Test that if file already exists, it returns immediately without S3 call"""
        file = MockFile("test.exe", b"test content")

        # Create file beforehand
        path_dir = os.path.join(self.temp_dir, "test_analyzer")
        os.makedirs(path_dir, exist_ok=True)
        _path = os.path.join(path_dir, "test.exe")
        with open(_path, "wb") as f:
            f.write(b"existing content")

        with patch("intel_owl.settings.storage.MEDIA_ROOT", self.temp_dir):
            path = self.storage.retrieve(file, "test_analyzer")

        # Verify S3 was not called
        mock_exists.assert_not_called()
        mock_open.assert_not_called()

        # Verify returned path is correct
        self.assertEqual(path, _path)

    @patch.object(S3Boto3StorageWrapper, "exists")
    def test_file_not_in_s3_raises_error(self, mock_exists):
        """Test that missing S3 file raises descriptive error"""
        file = MockFile("nonexistent.exe")
        mock_exists.return_value = False

        with patch("intel_owl.settings.storage.MEDIA_ROOT", self.temp_dir):
            with self.assertRaises(FileNotFoundError) as context:
                self.storage.retrieve(file, "test_analyzer")

            # Verify error message is descriptive
            error_msg = str(context.exception)
            self.assertIn("nonexistent.exe", error_msg)
            self.assertIn("S3", error_msg)

    @patch.object(S3Boto3StorageWrapper, "exists")
    @patch.object(S3Boto3StorageWrapper, "open")
    def test_double_check_pattern(self, mock_open, mock_exists):
        """Test that double-check pattern works correctly"""
        file = MockFile("test.exe", b"test content")
        mock_exists.return_value = True

        # Mock S3 file object
        mock_s3_file = Mock()
        mock_s3_file.read.return_value = b"test content"
        mock_s3_file.__enter__ = Mock(return_value=mock_s3_file)
        mock_s3_file.__exit__ = Mock(return_value=False)
        mock_open.return_value = mock_s3_file

        with patch("intel_owl.settings.storage.MEDIA_ROOT", self.temp_dir):
            # First call downloads the file
            path1 = self.storage.retrieve(file, "test_analyzer")

            # Second call should use existing file (double-check)
            path2 = self.storage.retrieve(file, "test_analyzer")

        # Both should return same path
        self.assertEqual(path1, path2)

        # S3 should only be called once (first call)
        self.assertEqual(mock_open.call_count, 1)

    @patch.object(S3Boto3StorageWrapper, "exists")
    @patch.object(S3Boto3StorageWrapper, "open")
    def test_atomic_write_with_temp_file(self, mock_open, mock_exists):
        """Test that file is written atomically using temp file"""
        file = MockFile("test.exe", b"test content")
        mock_exists.return_value = True

        # Mock S3 file object
        mock_s3_file = Mock()
        mock_s3_file.read.return_value = b"test content"
        mock_s3_file.__enter__ = Mock(return_value=mock_s3_file)
        mock_s3_file.__exit__ = Mock(return_value=False)
        mock_open.return_value = mock_s3_file

        path_dir = os.path.join(self.temp_dir, "test_analyzer")
        _path = os.path.join(path_dir, "test.exe")
        temp_path = f"{_path}.tmp"

        with patch("intel_owl.settings.storage.MEDIA_ROOT", self.temp_dir):
            path = self.storage.retrieve(file, "test_analyzer")

        # Verify temp file was cleaned up
        self.assertFalse(os.path.exists(temp_path))

        # Verify final file exists
        self.assertTrue(os.path.exists(_path))
        self.assertEqual(path, _path)

    @patch.object(S3Boto3StorageWrapper, "exists")
    @patch.object(S3Boto3StorageWrapper, "open")
    def test_concurrent_directory_creation(self, mock_open, mock_exists):
        """Test that concurrent directory creation doesn't raise FileExistsError"""
        file = MockFile("test.exe", b"test content")
        mock_exists.return_value = True

        # Mock S3 file object
        mock_s3_file = Mock()
        mock_s3_file.read.return_value = b"test content"
        mock_s3_file.__enter__ = Mock(return_value=mock_s3_file)
        mock_s3_file.__exit__ = Mock(return_value=False)
        mock_open.return_value = mock_s3_file

        with patch("intel_owl.settings.storage.MEDIA_ROOT", self.temp_dir):
            # Multiple analyzers creating directories simultaneously
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [
                    executor.submit(
                        self.storage.retrieve, file, f"analyzer_{i}"
                    )
                    for i in range(10)
                ]
                # Should not raise FileExistsError
                paths = [f.result() for f in futures]

        # Verify all files exist
        self.assertTrue(all(os.path.exists(p) for p in paths))
