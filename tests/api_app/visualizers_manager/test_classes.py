# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from kombu import uuid

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerReport
from api_app.choices import Classification, PythonModuleBasePaths
from api_app.models import Job, PythonModule
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.visualizers_manager.classes import (
    VisualizableBase,
    VisualizableBool,
    VisualizableDownload,
    VisualizableHorizontalList,
    VisualizableImage,
    VisualizableLevel,
    VisualizableLevelSize,
    VisualizableObject,
    VisualizablePage,
    VisualizableTable,
    VisualizableTableColumn,
    VisualizableTitle,
    VisualizableVerticalList,
    Visualizer,
)
from api_app.visualizers_manager.decorators import (
    visualizable_error_handler_with_params,
)
from api_app.visualizers_manager.enums import (
    VisualizableColor,
    VisualizableSize,
    VisualizableTableColumnSize,
)
from api_app.visualizers_manager.models import VisualizerConfig
from tests import CustomTestCase


class VisualizableObjectTestCase(CustomTestCase):
    class MockUpVisualizableObject(VisualizableObject):
        @property
        def type(self):
            return "test"

    def test_to_dict(self):
        vo = self.MockUpVisualizableObject(size=VisualizableSize.S_1, disable=False)
        result = vo.to_dict()

        expected_result = {
            "alignment": "around",
            "size": "1",
            "disable": False,
            "type": "test",
        }
        self.assertEqual(expected_result, result)


class VisualizableBaseTestCase(CustomTestCase):
    def test_to_dict(self):
        # no link
        vo = VisualizableBase(
            "test",
            color=VisualizableColor.DARK,
            disable=True,
            description="description-test",
        )
        expected_result = {
            "alignment": "center",
            "disable": True,
            "bold": False,
            "italic": False,
            "type": "base",
            "value": "test",
            "color": "dark",
            "size": "auto",
            "link": "",
            "icon": "",
            "copy_text": "test",
            "description": "description-test",
        }
        self.assertEqual(vo.to_dict(), expected_result)

        # link
        vb = VisualizableBase(
            "test",
            color=VisualizableColor.DARK,
            link="https://test.com",
            disable=True,
            description="description-test",
        )
        expected_result = {
            "alignment": "center",
            "disable": True,
            "bold": False,
            "italic": False,
            "type": "base",
            "value": "test",
            "color": "dark",
            "size": "auto",
            "link": "https://test.com",
            "icon": "",
            "copy_text": "https://test.com",
            "description": "description-test",
        }
        self.assertEqual(vb.to_dict(), expected_result)

    def test_empty(self):
        vo = VisualizableBase(
            "",
            color=VisualizableColor.DARK,
            link="https://test.com",
            disable=False,
        )
        expected_result = {}
        self.assertEqual(vo.to_dict(), expected_result)

    def test_disable(self):
        vo = VisualizableBase(
            value="",
            color=VisualizableColor.DARK,
            size=VisualizableSize.S_3,
            link="https://test.com",
            disable=True,
            copy_text="no text",
        )
        expected_result = {
            "alignment": "center",
            "disable": True,
            "bold": False,
            "italic": False,
            "type": "base",
            "value": "",
            "color": "dark",
            "size": "3",
            "link": "https://test.com",
            "icon": "",
            "copy_text": "no text",
            "description": "",
        }
        self.assertEqual(vo.to_dict(), expected_result)


class VisualizableDownloadTestCase(CustomTestCase):
    def test_to_dict(self):
        vo = VisualizableDownload(
            value="hello.txt",
            payload="hello, world",
            link="https://test.com",
            disable=True,
            description="description-test",
        )
        expected_result = {
            "alignment": "center",
            "disable": True,
            "type": "download",
            "value": "hello.txt",
            "size": "auto",
            "link": "https://test.com",
            "copy_text": "",
            "payload": "hello, world",
            "mimetype": "text/plain",
            "description": "description-test",
            "add_metadata_in_description": True,
        }
        self.assertEqual(vo.to_dict(), expected_result)

    def test_empty(self):
        vo = VisualizableDownload(
            value="",
            payload="",
            disable=False,
        )
        expected_result = {
            "alignment": "center",
            "disable": False,
            "type": "download",
            "value": "",
            "size": "auto",
            "link": "",
            "copy_text": "",
            "payload": "",
            "mimetype": "application/x-empty",
            "description": "",
            "add_metadata_in_description": True,
        }
        self.assertEqual(vo.to_dict(), expected_result)

    def test_disable(self):
        vo = VisualizableDownload(
            value="",
            payload="hello, world",
            size=VisualizableSize.S_3,
            disable=True,
        )
        expected_result = {
            "alignment": "center",
            "disable": True,
            "type": "download",
            "value": "",
            "size": "3",
            "link": "",
            "payload": "hello, world",
            "copy_text": "",
            "description": "",
            "mimetype": "text/plain",
            "add_metadata_in_description": True,
        }
        self.assertEqual(vo.to_dict(), expected_result)


class VisualizableBoolTestCase(CustomTestCase):
    def test_to_dict(self):
        vo = VisualizableBool(value="test", disable=False)
        expected_result = {
            "type": "bool",
            "value": "test",
            "link": "",
            "color": "danger",
            "icon": "",
            "italic": False,
            "size": "auto",
            "disable": False,
            "copy_text": "test",
            "description": "",
        }
        self.assertEqual(vo.to_dict(), expected_result)


class VisualizableTitleTestCase(CustomTestCase):
    def test_to_dict(self):
        title = VisualizableBase(value="test_title", color=VisualizableColor.DARK, link="http://test_title")

        value = VisualizableBase(value="test_value", color=VisualizableColor.DANGER, link="http://test_value")

        vo = VisualizableTitle(title, value)

        expected_result = {
            "alignment": "center",
            "type": "title",
            "title": title.to_dict(),
            "value": value.to_dict(),
            "size": "auto",
            "disable": True,
        }
        self.assertEqual(vo.to_dict(), expected_result)


class VisualizableVerticalListTestCase(CustomTestCase):
    def test_to_dict(self):
        name = VisualizableBase(value="test")
        value = VisualizableBase(value="test_value", color=VisualizableColor.DANGER, link="http://test_value")
        vvl = VisualizableVerticalList(name=name, value=[value])
        expected_result = {
            "alignment": "center",
            "type": "vertical_list",
            "name": name.to_dict(),
            "start_open": False,
            "disable": True,
            "size": "auto",
            "values": [value.to_dict()],
        }
        self.assertEqual(vvl.to_dict()["values"], vvl.to_dict()["values"])
        self.assertNotEqual(0, len(vvl.to_dict()["values"]))
        self.assertEqual(vvl.to_dict(), expected_result)

    def test_to_dict_values_null(self):
        name = VisualizableBase(value="test")
        value = VisualizableBase(value="", color=VisualizableColor.DANGER, link="http://test_value")
        vvl = VisualizableVerticalList(name=name, value=[value])
        expected_result = {
            "alignment": "center",
            "type": "vertical_list",
            "name": name.to_dict(),
            "disable": True,
            "start_open": False,
            "size": "auto",
            "values": [],
        }
        self.assertCountEqual(vvl.to_dict(), expected_result)

    def test_to_dict_values_empty(self):
        name = VisualizableBase(value="test")
        vvl = VisualizableVerticalList(name=name, value=[])
        expected_result = {
            "alignment": "center",
            "type": "vertical_list",
            "name": name.to_dict(),
            "disable": True,
            "start_open": False,
            "size": "auto",
            "values": [
                {
                    "alignment": "center",
                    "bold": False,
                    "color": "",
                    "disable": True,
                    "icon": "",
                    "italic": False,
                    "link": "",
                    "size": "auto",
                    "type": "base",
                    "value": "no data available",
                    "copy_text": "no data available",
                    "description": "",
                }
            ],
        }
        self.assertEqual(vvl.to_dict(), expected_result)

    def test_to_dict_name_null(self):
        value = VisualizableBase(value="", color=VisualizableColor.DANGER, link="http://test_value")
        vvl = VisualizableVerticalList(value=[value])
        expected_result = {
            "alignment": "center",
            "type": "vertical_list",
            "name": None,
            "disable": True,
            "start_open": True,
            "size": "auto",
            "values": [],
        }
        self.assertEqual(vvl.to_dict(), expected_result)


class VisualizableTableTestCase(CustomTestCase):
    def test_to_dict(self):
        data = [{"column_name": VisualizableBase(value="test_value", color=VisualizableColor.DANGER)}]
        columns = [
            VisualizableTableColumn(
                name="column_name",
                description="test description",
                max_width=VisualizableTableColumnSize.S_300,
                disable_filters=True,
                disable_sort_by=True,
            ),
        ]
        vvl = VisualizableTable(columns=columns, data=data, sort_by_desc=True, sort_by_id="column_name")
        expected_result = {
            "size": "auto",
            "alignment": "around",
            "columns": [
                {
                    "name": "column_name",
                    "max_width": 300,
                    "description": "test description",
                    "disable_filters": True,
                    "disable_sort_by": True,
                }
            ],
            "page_size": 5,
            "sort_by_id": "column_name",
            "sort_by_desc": True,
            "type": "table",
            "data": [
                {
                    "column_name": {
                        "size": "auto",
                        "alignment": "center",
                        "disable": True,
                        "value": "test_value",
                        "color": "danger",
                        "link": "",
                        "icon": "",
                        "bold": False,
                        "italic": False,
                        "copy_text": "test_value",
                        "description": "",
                        "type": "base",
                    }
                }
            ],
        }
        self.assertEqual(vvl.to_dict(), expected_result)

    def test_to_dict_data_null(self):
        columns = [
            VisualizableTableColumn(
                name="column_name",
                description="test description",
            ),
        ]
        vvl = VisualizableTable(columns=columns, data=[])
        expected_result = {
            "size": "auto",
            "alignment": "around",
            "columns": [
                {
                    "name": "column_name",
                    "max_width": 300,
                    "description": "test description",
                    "disable_filters": False,
                    "disable_sort_by": False,
                }
            ],
            "page_size": 5,
            "type": "table",
            "data": [],
            "sort_by_id": "",
            "sort_by_desc": False,
        }
        self.assertCountEqual(vvl.to_dict(), expected_result)


class VisualizableHorizontalListTestCase(CustomTestCase):
    def test_to_dict(self):
        value = VisualizableBase(value="test_value", color=VisualizableColor.DANGER, link="http://test_value")
        vvl = VisualizableHorizontalList(value=[value])
        expected_result = {
            "type": "horizontal_list",
            "alignment": "around",
            "values": [value.to_dict()],
        }
        self.assertEqual(vvl.to_dict(), expected_result)

    def test_to_dict_values_null(self):
        vvl = VisualizableHorizontalList(value=[])
        expected_result = {
            "type": "horizontal_list",
            "alignment": "around",
            "values": [],
        }
        self.assertEqual(vvl.to_dict(), expected_result)

    def test_to_dict_values_empty(self):
        vvl = VisualizableHorizontalList(value=[])
        expected_result = {
            "type": "horizontal_list",
            "alignment": "around",
            "values": [],
        }
        self.assertEqual(vvl.to_dict(), expected_result)


class VisualizableLevelTestCase(CustomTestCase):
    def test_to_dict(self):
        value = VisualizableBase(value="test_value", color=VisualizableColor.DANGER, link="http://test_value")
        vvl = VisualizableHorizontalList(value=[value])
        level = VisualizableLevel(position=1, size=VisualizableLevelSize.S_2, horizontal_list=vvl)
        expected_result = {
            "level_position": 1,
            "level_size": "2",
            "elements": vvl.to_dict(),
        }
        self.assertEqual(level.to_dict(), expected_result)


class VisualizablePageTestCase(CustomTestCase):
    def test_to_dict(self):
        value = VisualizableBase(value="test_value", color=VisualizableColor.DANGER, link="http://test_value")
        vvl = VisualizableHorizontalList(value=[value])
        vl = VisualizablePage()
        vl.add_level(VisualizableLevel(position=1, size=VisualizableLevelSize.S_2, horizontal_list=vvl))
        expected_result = {
            "level_position": 1,
            "level_size": "2",
            "elements": vvl.to_dict(),
        }
        self.assertEqual(vl.to_dict()[1][0], expected_result)


class VisualizerTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    def test_analyzer_reports(self):
        class MockUpVisualizer(Visualizer):
            def run(self) -> dict:
                return {}

        pc = PlaybookConfig.objects.first()
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )
        job = Job.objects.create(
            analyzable=an,
            status="reported_without_fails",
        )
        vc = VisualizerConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Visualizer.value, module="yara.Yara"
            ),
            description="test",
        )
        ar = AnalyzerReport.objects.create(
            config=pc.analyzers.first(),
            job=job,
            task_id=uuid(),
            parameters={},
        )
        v = MockUpVisualizer(vc)
        v.job_id = job.pk
        self.assertEqual(list(v.get_analyzer_reports()), [ar])
        ar.delete()
        job.delete()
        vc.delete()
        an.delete()

    def test_subclasses(self):
        def handler(signum, frame):
            raise TimeoutError("end of time")

        import signal

        signal.signal(signal.SIGALRM, handler)

        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )
        job = Job.objects.create(
            analyzable=an,
            status="reported_without_fails",
            user=self.superuser,
        )

        subclasses = Visualizer.all_subclasses()
        for subclass in subclasses:
            print(f"\nTesting Visualizer {subclass.__name__}")
            configs = VisualizerConfig.objects.filter(python_module=subclass.python_module)
            if not configs.exists():
                self.fail(f"There is a python module {subclass.python_module} without any configuration")
            for config in configs:
                job.visualizers_to_execute.set([config])
                timeout_seconds = config.soft_time_limit
                timeout_seconds = min(timeout_seconds, 20)
                print(f"\tTesting with config {config.name} for {timeout_seconds} seconds")
                sub = subclass(config)
                signal.alarm(timeout_seconds)
                try:
                    sub.start(job.pk, {}, uuid())
                except Exception as e:
                    self.fail(f"Visualizer {subclass.__name__} with config {config.name} failed {e}")
                finally:
                    signal.alarm(0)

        job.delete()
        an.delete()


class ErrorHandlerTestCase(CustomTestCase):
    class TestClass:
        @property
        @visualizable_error_handler_with_params()
        def no_error(self):
            return VisualizableBool(value="test", disable=False, color=VisualizableColor.SUCCESS)

        @property
        @visualizable_error_handler_with_params("error component", error_size=VisualizableSize.S_2)
        def error(self):
            raise Exception("this is an exception to test the error")

    def test_without_error(self):
        result = self.TestClass().no_error
        self.assertEqual(
            result.to_dict(),
            {
                "size": "auto",
                "disable": False,
                "value": "test",
                "color": "success",
                "link": "",
                "icon": "",
                "italic": False,
                "type": "bool",
                "copy_text": "test",
                "description": "",
            },
        )

    def test_with_error(self):
        result = self.TestClass().error
        self.assertEqual(
            result.to_dict(),
            {
                "size": "2",
                "alignment": "center",
                "disable": True,
                "title": {
                    "size": "auto",
                    "alignment": "center",
                    "disable": True,
                    "value": "error component",
                    "color": "",
                    "link": "",
                    "icon": "",
                    "bold": False,
                    "italic": False,
                    "type": "base",
                    "copy_text": "error component",
                    "description": "",
                },
                "value": {
                    "size": "auto",
                    "alignment": "center",
                    "disable": True,
                    "value": "error",
                    "color": "danger",
                    "link": "",
                    "icon": "",
                    "bold": False,
                    "italic": False,
                    "type": "base",
                    "copy_text": "error",
                    "description": "",
                },
                "type": "title",
            },
        )


class VisualizableTableColumnTestCase(CustomTestCase):
    def test_to_dict(self):
        co = VisualizableTableColumn(
            name="id",
            description="test description",
            max_width=VisualizableTableColumnSize.S_300,
            disable_filters=True,
            disable_sort_by=True,
        )
        result = co.to_dict()

        expected_result = {
            "name": "id",
            "description": "test description",
            "max_width": 300,
            "disable_filters": True,
            "disable_sort_by": True,
        }
        self.assertEqual(expected_result, result)


class VisualizableImageTestCase(CustomTestCase):
    def test_to_dict_with_url(self):
        img = VisualizableImage(
            url="https://example.com/image.png",
            title="Test Image",
            description="A test image",
            max_width=400,
            max_height=300,
            allow_expand=True,
        )
        result = img.to_dict()

        self.assertEqual(result["type"], "image")
        self.assertEqual(result["url"], "https://example.com/image.png")
        self.assertEqual(result["title"], "Test Image")
        self.assertEqual(result["description"], "A test image")
        self.assertEqual(result["max_width"], 400)
        self.assertEqual(result["max_height"], 300)
        self.assertEqual(result["allow_expand"], True)

    def test_to_dict_with_base64(self):
        img = VisualizableImage(
            base64="iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAA",
            title="Base64 Image",
        )
        result = img.to_dict()

        self.assertEqual(result["type"], "image")
        self.assertEqual(result["base64"], "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAA")
        self.assertEqual(result["url"], "")
        self.assertEqual(result["title"], "Base64 Image")

    def test_requires_url_or_base64(self):
        with self.assertRaises(ValueError) as context:
            VisualizableImage(title="No source")
        self.assertIn("url", str(context.exception).lower())

    def test_default_values(self):
        img = VisualizableImage(url="https://example.com/img.png")
        result = img.to_dict()

        self.assertEqual(result["max_width"], 500)
        self.assertEqual(result["max_height"], 400)
        self.assertEqual(result["allow_expand"], True)
        self.assertEqual(result["disable"], False)
        self.assertEqual(result["alignment"], "center")

    def test_disabled_image(self):
        img = VisualizableImage(
            url="https://example.com/img.png",
            disable=True,
        )
        result = img.to_dict()

        self.assertEqual(result["disable"], True)
