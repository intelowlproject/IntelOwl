from cache_memoize import cache_memoize

from .serializers import AnalyzerConfigSerializer


@cache_memoize(100)
def get_verified_analyzer_config():
    success, config = AnalyzerConfigSerializer.read_and_verify_config()

    return config
