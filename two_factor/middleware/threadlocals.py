from threading import local

_thread_locals = local()


def get_current_request():
    return getattr(_thread_locals, "request", None)


class ThreadLocals:
    """
    Middleware that stores the request object in thread local storage.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        _thread_locals.request = request
        return self.get_response(request)
