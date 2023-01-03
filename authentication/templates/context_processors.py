from intel_owl.settings import HOST_NAME, HOST_URI


def host(request):
    """
    Custom context processor that injects the
    ``HOST_URI`` and ``HOST_NAME`` setting variables into every template.
    """
    return {
        "host_uri": HOST_URI,
        "host_name": HOST_NAME,
    }
