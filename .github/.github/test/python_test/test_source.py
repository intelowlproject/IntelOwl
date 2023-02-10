import unittest

from django.test import tag

try:
    from .source import A
except ImportError:
    from source import A


class TestA(unittest.TestCase):
    def test_mya(self):
        a = A()
        self.assertEqual(a.my_a(), 1)

    @tag("main")
    def test_c(self):
        a = A()
        self.assertEqual(a.c, 3)

    @tag("manual")
    def test_b(self):
        a = A()
        self.assertEqual(a.b, 2)


class TestB(unittest.TestCase):
    def test_add_task(self):
        from python_test.celery import add

        rst = add.apply(args=(4, 4)).get()
        self.assertEqual(rst, 8)
