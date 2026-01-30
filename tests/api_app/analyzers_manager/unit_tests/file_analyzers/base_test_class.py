import hashlib
import logging
import os
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock

from django.utils import timezone

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import TLP

logger = logging.getLogger(__name__)


class BaseFileAnalyzerTest(TestCase):
    analyzer_class = None
    test_files_dir = "test_files"

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

    @classmethod
    def get_sample_file_path(cls, mimetype: str) -> str:
        filename = cls.MIMETYPE_TO_FILENAME.get(mimetype)
        if not filename:
            raise ValueError(f"No test file defined for mimetype {mimetype}")
        return os.path.join(cls.test_files_dir, filename)

    @classmethod
    def get_sample_file_bytes(cls, mimetype: str) -> bytes:
        path = cls.get_sample_file_path(mimetype)
        with open(path, "rb") as f:
            return f.read()

    @classmethod
    def get_all_supported_mimetypes(cls) -> set:
        """Returns all available mimetypes from the mapping"""
        return set(cls.MIMETYPE_TO_FILENAME.keys())

    @classmethod
    def get_extra_config(cls) -> dict:
        """
        Subclasses can override this to provide additional runtime configuration
        specific to their analyzer (e.g., API keys, URLs, retry counts, etc.).
        """
        return {}

    @classmethod
    def get_mocked_response(cls):
        """
        Subclasses override this to define expected mocked output.
        """
        raise NotImplementedError("Subclasses must implement get_mocked_response()")

    @classmethod
    def _apply_patches(cls, patches):
        """Helper method to apply single or multiple patches"""
        if patches is None:
            return ExitStack()  # No-op context manager

        if hasattr(patches, "__enter__") and hasattr(patches, "__exit__"):
            return patches

        if isinstance(patches, (list, tuple)):
            stack = ExitStack()
            for patch_obj in patches:
                stack.enter_context(patch_obj)
            return stack

        return patches

    def setUp(self):
        super().setUp()
        if self.analyzer_class:
            analyzer_module = self.analyzer_class.__module__
            logging.getLogger(analyzer_module).setLevel(logging.CRITICAL)
            logging.getLogger("api_app.analyzers_manager").setLevel(logging.WARNING)

    def tearDown(self):
        super().tearDown()
        if self.analyzer_class:
            analyzer_module = self.analyzer_class.__module__
            logging.getLogger(analyzer_module).setLevel(logging.NOTSET)
            logging.getLogger("api_app.analyzers_manager").setLevel(logging.NOTSET)

    def test_analyzer_on_supported_filetypes(self):
        if self.analyzer_class is None:
            self.skipTest(f"{self.__class__.__name__}: analyzer_class is not set")

        logger.info(f"Starting file analyzer test for: {self.analyzer_class.__name__}")

        try:
            configs = AnalyzerConfig.objects.filter(python_module=self.analyzer_class.python_module)
            config = configs.first()
        except AnalyzerConfig.DoesNotExist:
            self.fail(f"No AnalyzerConfig found for {self.analyzer_class.python_module}")

        logger.debug(f"Loaded analyzer config: {config}")

        supported_types = config.supported_filetypes or self.get_all_supported_mimetypes()

        for mimetype in supported_types:
            with self.subTest(mimetype=mimetype):
                logger.info(f"Testing mimetype: {mimetype}")

                try:
                    file_bytes = self.get_sample_file_bytes(mimetype)
                except (ValueError, OSError) as e:
                    logger.warning(f"Skipping {mimetype} due to error: {e}")
                    continue

                patches = self.get_mocked_response()
                with self._apply_patches(patches):
                    md5 = hashlib.md5(file_bytes).hexdigest()

                    analyzer = self.analyzer_class(config)
                    analyzer.file_mimetype = mimetype
                    analyzer.filename = f"test_file_{mimetype}"
                    analyzer.md5 = md5
                    analyzer.read_file_bytes = lambda file_bytes=file_bytes: file_bytes

                    analyzer._job = SimpleNamespace()
                    analyzer._job.TLP = TLP.CLEAR
                    analyzer._job.analyzable = SimpleNamespace()
                    analyzer._job.analyzable.name = analyzer.filename
                    analyzer._job.analyzable.mimetype = mimetype
                    analyzer._job.analyzable.sha256 = hashlib.sha256(file_bytes).hexdigest()
                    analyzer._job_id = ""
                    analyzer._job.tlp = "clear"
                    analyzer.report = MagicMock()
                    analyzer.report.report = {}
                    analyzer.report.errors = []
                    analyzer.report.status = ""
                    analyzer.report.end_time = timezone.now()

                    # Fake STATUSES enum
                    analyzer.report.STATUSES = MagicMock()
                    analyzer.report.STATUSES.FAILED = "failed"
                    analyzer.report.STATUSES.SUCCESS = "success"
                    analyzer._FileAnalyzer__filepath = self.get_sample_file_path(mimetype)

                    for key, value in self.get_extra_config().items():
                        setattr(analyzer, key, value)

                    try:
                        response = analyzer.run()
                        analyzer.report.report = response
                        logger.info(f"Analyzer ran successfully for {mimetype}")
                    except Exception as e:
                        analyzer.report.errors.append(
                            f"Analyzer run failed for {mimetype}: {type(e).__name__}: {e}"
                        )
                        logger.exception(f"Analyzer raised an exception for {mimetype}")
                        self.fail(f"Analyzer run failed for {mimetype}: {type(e).__name__}: {e}")
                    self.assertTrue(
                        analyzer.report,
                        f"Analyzer response for {mimetype} should not be empty",
                    )
                    logger.debug(f"Successful result for {mimetype}: {response}")
