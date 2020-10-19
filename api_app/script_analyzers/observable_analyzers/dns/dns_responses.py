"""These are the default responses"""


def malicious_detector_response(observable: str, malicious: bool) -> dict:
    """Standard response for malicious detector analyzers

    :param observable: observable analyzed
    :type observable: str
    :param malicious: tell if the observable is reported as malicious from analyzer
    :type malicious: bool
    :return:
    :rtype: dict
    """

    return {"observable": observable, "malicious": malicious}


def dns_resolver_response(observable: str, resolutions: list = None) -> dict:
    """Standard response for DNS resolver analyzers

    :param observable: observable analyzed
    :type observable: str
    :param resolutions: list of DNS resolutions, it is empty in case of no resolutions,
    default to None
    :type resolutions: list, optional
    :return:
    :rtype: dict
    """

    if not resolutions:
        resolutions = []

    return {"observable": observable, "resolutions": resolutions}
