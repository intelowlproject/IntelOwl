import hashlib
import os
from contextlib import ExitStack
from unittest import TestCase

from api_app.analyzers_manager.models import AnalyzerConfig


class BaseFileAnalyzerTest(TestCase):
    analyzer_class = None
    test_files_dir = "test_files"

    @classmethod
    def get_sample_file_path(cls, mimetype: str) -> str:
        # Match mimetype → filename from your FileAnalyzerTestCase
        MIMETYPE_TO_FILENAME = {
            "application/onenote": "sample.one",
            "application/x-sharedlib": "ping.elf",
            "application/vnd.tcpdump.pcap": "example.pcap",
            "application/vnd.android.package-archive": "sample.apk",
            "application/javascript": "file.jse",
            "text/html": "page.html",
            "application/pdf": "document.pdf",
            "text/rtf": "document.rtf",
            "application/vnd.ms-excel": "document.xls",
            "application/msword": "document.doc",
            "application/x-ms-shortcut": "downloader.lnk",
            "application/vnd.microsoft.portable-executable": "file.dll",
            "application/octet-stream": "shellcode.bin",
            "message/rfc822": "Sublime-Standard-Test-String.eml",
            "text/plain": "textfile.txt",
            "application/x-chrome-extension": "sample.crx",
            "application/json": "manifest.json",
            "application/x-executable": "main.out",
            "text/x-java": "java_vuln.java",
            "text/x-kotlin": "kotlin.kt",
            "text/x-objective-c": "objectivec.m",
            "text/x-swift": "swift.swift",
            "text/xml": "android.xml",
            "application/zip": "test.zip",
            "application/x-dex": "sample.dex",
        }

        filename = MIMETYPE_TO_FILENAME.get(mimetype)
        if not filename:
            raise ValueError(f"No test file defined for mimetype {mimetype}")
        return os.path.join(cls.test_files_dir, filename)

    @classmethod
    def get_sample_file_bytes(cls, mimetype: str) -> bytes:
        path = cls.get_sample_file_path(mimetype)
        with open(path, "rb") as f:
            return f.read()

    def get_mocked_response(self):
        """
        Subclasses override this to define expected mocked output.

        Can return:
        1. A single patch object: patch('module.function')
        2. A list of patch objects: [patch('module.func1'), patch('module.func2')]
        3. A context manager: patch.multiple() or ExitStack()
        """
        raise NotImplementedError

    def _apply_patches(self, patches):
        """Helper method to apply single or multiple patches"""
        if patches is None:
            return ExitStack()  # No-op context manager

        # If it's already a context manager, return as-is
        if hasattr(patches, "__enter__") and hasattr(patches, "__exit__"):
            return patches

        # If it's a list of patches, use ExitStack to manage them
        if isinstance(patches, (list, tuple)):
            stack = ExitStack()
            for patch_obj in patches:
                stack.enter_context(patch_obj)
            return stack

        # Single patch object
        return patches

    def test_analyzer_on_supported_filetypes(self):
        if self.analyzer_class is None:
            self.skipTest("analyzer_class is not set")
        config = AnalyzerConfig.objects.get(
            python_module=self.analyzer_class.python_module
        )

        for mimetype in config.supported_filetypes:
            with self.subTest(mimetype=mimetype):
                try:
                    file_bytes = self.get_sample_file_bytes(mimetype)
                except (ValueError, FileNotFoundError, OSError):
                    print(f"SKIPPING {mimetype}")
                    continue

                md5 = hashlib.md5(file_bytes).hexdigest()

                analyzer = self.analyzer_class(config)
                analyzer.file_mimetype = mimetype
                analyzer.filename = f"test_file_{mimetype}"
                analyzer.md5 = md5
                analyzer.read_file_bytes = lambda: file_bytes

                # Set up filepath for analyzers that need it
                test_file_path = self.get_sample_file_path(mimetype)
                analyzer._FileAnalyzer__filepath = test_file_path

                # Apply patches using the improved system
                patches = self.get_mocked_response()
                with self._apply_patches(patches):
                    response = analyzer.run()
                    self.assertTrue(response)
                    print(f"SUCCESS {mimetype}")
