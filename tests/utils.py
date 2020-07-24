# utils.py: useful utils for mocking requests and responses for testing

# class for mocking responses
class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code
        self.text = ""
        self.content = b""

    def json(self):
        return self.json_data

    def raise_for_status(self):
        pass


# a mock response class that has no operation
class MockResponseNoOp:
    def __init__(self, json_data, status_code):
        pass

    def search(self, **kwargs):
        return {}

    def query(self, val):
        return {}


def mocked_requests(*args, **kwargs):
    return MockResponse({}, 200)


def mocked_docker_analyzer_get(*args, **kwargs):
    return MockResponse(
        {"key": "test", "returncode": 0, "report": {"test": "This is a test."}}, 200
    )


def mocked_docker_analyzer_post(*args, **kwargs):
    return MockResponse({"key": "test", "status": "running"}, 202)
