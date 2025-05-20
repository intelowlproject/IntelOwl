# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from django.core.files import File
from kombu import uuid

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.classes import FileAnalyzer, ObservableAnalyzer
from api_app.analyzers_manager.models import AnalyzerConfig, MimeTypes
from api_app.choices import Classification
from api_app.models import Job, PluginConfig
from tests import CustomTestCase


class MockUpObservableAnalyzer(ObservableAnalyzer):
    def run(self) -> dict:
        return {}

    @classmethod
    def update(cls) -> bool:
        pass


class FileAnalyzerTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    def setUp(self) -> None:
        super().setUp()
        # we need to not sleep at the beginning for too long
        # otherwise the test goes into TimeoutError
        PluginConfig.objects.filter(
            analyzer_config__name="CapeSandbox", parameter__name="timeout"
        ).update(value=10)

    def _create_jobs(self):
        for sample_name, mimetype in zip(
            [
                "sample.one",
                "ping.elf",
                "example.pcap",
                "sample.apk",
                "file.jse",
                "page.html",
                "document.pdf",
                "document.rtf",
                "document.xls",
                "document.doc",
                "downloader.lnk",
                "file.dll",
                "file.exe",
                "shellcode.bin",
                "Sublime-Standard-Test-String.eml",
                "textfile.txt",
                "AndroidManifest.xml",
                "sample.crx",
                "manifest.json",
                "main.out",
                "java_vuln.java",
                "kotlin.kt",
                "objectivec.m",
                "swift.swift",
                "android.xml",
                "test.zip",
                "sample.dex",
            ],
            [
                "application/onenote",
                "application/x-sharedlib",
                "application/vnd.tcpdump.pcap",
                "application/vnd.android.package-archive",
                "application/javascript",
                "text/html",
                "application/pdf",
                "text/rtf",
                "application/vnd.ms-excel",
                "application/msword",
                "application/x-ms-shortcut",
                "application/vnd.microsoft.portable-executable",
                "application/vnd.microsoft.portable-executable",
                "application/octet-stream",
                "message/rfc822",
                "text/plain",
                "application/octet-stream",
                "application/x-chrome-extension",
                "application/json",
                "application/x-executable",
                "text/x-java",
                "text/x-kotlin",
                "text/x-objective-c",
                "text/x-swift",
                "text/xml",
                "application/zip",
                "application/x-dex",
            ],
        ):
            try:
                with open(f"test_files/{sample_name}", "rb") as f:
                    an = Analyzable.objects.create(
                        file=File(f),
                        name=sample_name,
                        mimetype=mimetype,
                        classification=Classification.FILE,
                    )
                    Job.objects.create(
                        analyzable=an,
                        user=self.superuser,
                    )

                    print(f"Created job for {sample_name}, with mimetype {mimetype}")
            except Exception:
                self.fail(f"No defined file for mimetype {mimetype}")

    def test_subclasses(self):
        def handler(signum, frame):
            raise TimeoutError("end of time")

        import signal

        signal.signal(signal.SIGALRM, handler)
        self._create_jobs()
        for subclass in FileAnalyzer.all_subclasses():
            print(f"\nTesting Analyzer {subclass.__name__}")
            configs = AnalyzerConfig.objects.filter(
                python_module=subclass.python_module
            )
            if not configs.exists():
                self.fail(
                    f"There is a python module {subclass.python_module}"
                    " without any configuration"
                )
            for config in configs:
                timeout_seconds = config.soft_time_limit
                timeout_seconds = min(timeout_seconds, 30)
                print(f"\tTesting with config {config.name}")
                found_one = False
                skipped = False
                for mimetype in MimeTypes.values:
                    if (
                        config.supported_filetypes
                        and mimetype in config.supported_filetypes
                    ):
                        pass
                    elif (
                        not config.supported_filetypes
                        and mimetype not in config.not_supported_filetypes
                    ):
                        pass
                    else:
                        continue
                    sub = subclass(
                        config,
                    )
                    if config.docker_based and not sub.health_check():
                        print(f"skipping {subclass.__name__} cause health check failed")
                        skipped = True
                        continue
                    jobs = Job.objects.filter(analyzable__mimetype=mimetype)
                    if jobs.exists():
                        found_one = True
                    for job in jobs:
                        job.analyzers_to_execute.set([config])
                        print(
                            "\t\t"
                            f"Testing {job.analyzable.name} with mimetype {mimetype}"
                            f" for {timeout_seconds} seconds"
                        )
                        signal.alarm(timeout_seconds)
                        try:
                            sub.start(job.pk, {}, uuid())
                        except Exception as e:
                            self.fail(
                                f"Analyzer {subclass.__name__} "
                                f"with config {config.name} and mimetype "
                                f"{mimetype} failed {e}"
                            )
                        finally:
                            signal.alarm(0)
                if not found_one and not skipped:
                    self.fail(
                        f"No valid job found for analyzer {subclass.__name__}"
                        f" with configuration {config.name}"
                    )

    def tearDown(self) -> None:
        Job.objects.all().delete()
        super().tearDown()


class ObservableAnalyzerTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    def test_config(self):
        config = AnalyzerConfig.objects.first()
        an1 = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )
        job = Job.objects.create(analyzable=an1)
        oa = MockUpObservableAnalyzer(config)
        oa.job_id = job.pk
        oa.config({})
        self.assertEqual(oa.observable_name, "test.com")
        self.assertEqual(oa.observable_classification, "domain")
        job.delete()
        an1.delete()

    def _create_jobs(self):
        an1 = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )
        an2 = Analyzable.objects.create(
            name="8.8.8.8",
            classification=Classification.IP,
        )
        an3 = Analyzable.objects.create(
            name="https://www.honeynet.org/projects/active/intel-owl/",
            classification=Classification.URL,
        )
        an4 = Analyzable.objects.create(
            name="3edd95917241e9ef9bbfc805c2c5aff3",
            classification=Classification.HASH,
        )
        an5 = Analyzable.objects.create(
            name="test@intelowl.com",
            classification=Classification.GENERIC,
        )
        an6 = Analyzable.objects.create(
            name="CVE-2024-51181",
            classification=Classification.GENERIC,
        )
        an7 = Analyzable.objects.create(
            name=51181,
            classification=Classification.GENERIC,
        )

        Job.objects.create(
            user=self.superuser,
            analyzable=an1,
            status="reported_without_fails",
        )
        Job.objects.create(
            user=self.superuser,
            analyzable=an2,
            status="reported_without_fails",
        )
        Job.objects.create(
            user=self.superuser,
            analyzable=an3,
            status="reported_without_fails",
        )
        Job.objects.create(
            user=self.superuser,
            analyzable=an4,
            status="reported_without_fails",
        )
        Job.objects.create(
            user=self.superuser,
            analyzable=an5,
            status="reported_without_fails",
        ),
        Job.objects.create(
            user=self.superuser,
            analyzable=an6,
            status="reported_without_fails",
        )
        Job.objects.create(
            user=self.superuser,
            analyzable=an7,
            status="reported_without_fails",
        )

    def test_subclasses(self):
        def handler(signum, frame):
            raise TimeoutError("end of time")

        import signal

        signal.signal(signal.SIGALRM, handler)
        self._create_jobs()
        for subclass in ObservableAnalyzer.all_subclasses():
            print(f"\nTesting Analyzer {subclass.__name__}")
            for config in AnalyzerConfig.objects.filter(
                python_module=subclass.python_module
            ):
                timeout_seconds = config.soft_time_limit
                timeout_seconds = min(timeout_seconds, 20)
                print("\t" f"Testing with config {config.name}")
                for observable_supported in config.observable_supported:
                    print(
                        "\t\t"
                        f"Testing datatype {observable_supported}"
                        f" for {timeout_seconds} seconds"
                    )
                    if observable_supported == Classification.GENERIC.value:
                        if config.name == "NVD_CVE":
                            name = "CVE-2024-51181"
                        elif config.name == "Spamhaus_DROP":
                            name = 51181
                        else:
                            name = "test@intelowl.com"

                        # generic should handle different use cases
                        job = Job.objects.get(
                            analyzable__classification=Classification.GENERIC.value,
                            analyzable__name=name,
                        )
                    else:
                        job = Job.objects.get(
                            analyzable__classification=observable_supported
                        )
                    job.analyzers_to_execute.set([config])
                    sub = subclass(
                        config,
                    )
                    signal.alarm(timeout_seconds)
                    try:
                        sub.start(job.pk, {}, uuid())
                    except TimeoutError:
                        self.fail(
                            f"Analyzer {subclass.__name__}"
                            f" with config {config.name}"
                            f" and observable {observable_supported}"
                            f" went in timeout after {timeout_seconds}"
                        )
                    finally:
                        signal.alarm(0)

    @staticmethod
    def tearDown() -> None:
        Job.objects.all().delete()
        Analyzable.objects.all().delete()
