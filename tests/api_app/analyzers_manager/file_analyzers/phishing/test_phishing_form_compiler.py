from unittest import TestCase

from api_app.analyzers_manager.file_analyzers.phishing.phishing_form_compiler import (
    PhishingFormCompiler,
)


class PhishingFormCompilerTestCase(TestCase):

    def test_extract_action_attribute_url(self):
        # for this test we'll treat "form" parameter as a dict
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
            PhishingFormCompiler.extract_action_attribute(
                "https://test.com/", {"action": "/test.php"}
            ),
            "https://test.com/test.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "https://test.com", {"action": "/test.php"}
            ),
            "https://test.com/test.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "https://test.com/", {"action": "test.php"}
            ),
            "test.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "https://test.com", {"action": "test.php"}
            ),
            "test.php",
        )
        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "https://test.com/", {"action": "/test"}
            ),
            "https://test.com/test",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "https://test.com", {"action": "/test"}
            ),
            "https://test.com/test",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "https://test.com/", {"action": "test"}
            ),
            "https://test.com/test",
        )

    def test_extract_action_attribute_domain(self):
        # for this test we'll treat "form" parameter as a dict
        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "test.com", {"action": "https://test2.com"}
            ),
            "https://test2.com",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "test.com", {"action": "https://test2.com/"}
            ),
            "https://test2.com/",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "test.com/", {"action": "/test.php"}
            ),
            "test.com/test.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "test.com", {"action": "/test.php"}
            ),
            "test.com/test.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "test.com/", {"action": "test.php"}
            ),
            "test.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "test.com", {"action": "test.php"}
            ),
            "test.php",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "test.com/", {"action": "/test"}
            ),
            "test.com/test",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "test.com", {"action": "/test"}
            ),
            "test.com/test",
        )

        self.assertEqual(
            PhishingFormCompiler.extract_action_attribute(
                "test.com/", {"action": "test"}
            ),
            "test.com/test",
        )
