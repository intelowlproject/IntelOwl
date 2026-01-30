from unittest import TestCase

from api_app.analyzers_manager.file_analyzers.phishing.phishing_form_compiler import (
    PhishingFormCompiler,
)


class PhishingFormCompilerTestCase(TestCase):
    def test_extract_action_attribute_url(self):
        # for this test we'll treat "form" parameter as a dict
        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("https://test.com", {"action": ""}),
            "https://test.com",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "https://test.com", {"action": "https://test2.com"}
            ),
            "https://test2.com",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "https://test.com", {"action": "https://test2.com/"}
            ),
            "https://test2.com/",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("https://test.com/", {"action": "/test.php"}),
            "https://test.com/test.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("https://test.com", {"action": "/test.php"}),
            "https://test.com/test.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("https://test.com/", {"action": "test.php"}),
            "https://test.com/test.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("https://test.com", {"action": "test.php"}),
            "https://test.com/test.php",
        )
        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("https://test.com/", {"action": "/test"}),
            "https://test.com/test",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("https://test.com", {"action": "/test"}),
            "https://test.com/test",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("https://test.com/", {"action": "test"}),
            "https://test.com/test",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "https://test.com/another", {"action": "https://test2.com"}
            ),
            "https://test2.com",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "https://test.com/another.php?test=y", {"action": "https://test2.com/"}
            ),
            "https://test2.com/",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "https://test.com/another.php?test=y", {"action": "/test2"}
            ),
            "https://test.com/test2",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "https://test.com/test.php/", {"action": "/test2.php"}
            ),
            "https://test.com/test2.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "https://test.com/test.php", {"action": "/test2.php"}
            ),
            "https://test.com/test2.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "https://test.com/test.php", {"action": "test.php"}
            ),
            "https://test.com/test.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "https://test.com/test.php/", {"action": "test.php"}
            ),
            "https://test.com/test.php/test.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("https://test.com/test.php", {"action": "/test"}),
            "https://test.com/test",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("https://test.com/test.php/", {"action": "/test"}),
            "https://test.com/test",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("https://test.com/test.php", {"action": "test"}),
            "https://test.com/test",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "https://test.com:11111/test.php", {"action": "test"}
            ),
            "https://test.com:11111/test",
        )

    def test_extract_action_attribute_domain(self):
        # for this test we'll treat "form" parameter as a dict
        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("test.com", {"action": ""}),
            "https://test.com",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("test.com", {"action": "https://test2.com"}),
            "https://test2.com",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("test.com", {"action": "https://test2.com/"}),
            "https://test2.com/",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("test.com/", {"action": "/test.php"}),
            "https://test.com/test.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("test.com", {"action": "/test.php"}),
            "https://test.com/test.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("test.com/", {"action": "test.php"}),
            "https://test.com/test.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("test.com", {"action": "test.php"}),
            "https://test.com/test.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("test.com/", {"action": "/test"}),
            "https://test.com/test",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("test.com", {"action": "/test"}),
            "https://test.com/test",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("test.com/", {"action": "test"}),
            "https://test.com/test",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "test.com/another", {"action": "https://test2.com"}
            ),
            "https://test2.com",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "test.com/another.php?test=y", {"action": "https://test2.com/"}
            ),
            "https://test2.com/",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "test.com/another.php?test=y", {"action": "/test2"}
            ),
            "https://test.com/test2",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("test.com/test.php/", {"action": "/test2.php"}),
            "https://test.com/test2.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("test.com/test.php", {"action": "/test2.php"}),
            "https://test.com/test2.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("test.com/test.php", {"action": "test.php"}),
            "https://test.com/test.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("test.com/test.php/", {"action": "test.php"}),
            "https://test.com/test.php/test.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("test.com/test.php", {"action": "/test"}),
            "https://test.com/test",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("test.com/test.php/", {"action": "/test"}),
            "https://test.com/test",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("test.com/test.php", {"action": "test"}),
            "https://test.com/test",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute("test.com:11111/test.php", {"action": "test"}),
            "https://test.com:11111/test",
        )
