import enum

from api_app.analyzers_manager.classes import FileAnalyzer, ObservableAnalyzer
from api_app.connectors_manager.classes import Connector
from api_app.ingestors_manager.classes import Ingestor
from api_app.visualizers_manager.classes import Visualizer


class PythonClasses(enum.Enum):
    OBSERVABLE_ANALYZER = ObservableAnalyzer
    FILE_ANALYZER = FileAnalyzer
    CONNECTOR = Connector
    VISUALIZER = Visualizer
    INGESTOR = Ingestor
