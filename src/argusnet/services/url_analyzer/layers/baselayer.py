# src/argusnet/services/url_analyzer/layers/baselayer.py

from abc import ABC, abstractmethod
import logging

class BaseLayer(ABC):
    
    """
    Base class for all intelligence layers in ArgusNet.
    Each layer must asynchronously enrich the report.
    """

    name: str = "Unnamed Layer"

    @abstractmethod
    async def run(self, report):
        """
        Receives the current report context.
        Must return the enriched report.
        """
        pass

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)