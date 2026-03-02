# src/argusnet/core/interfaces.py

"""
Service interface definitions for ArgusNet
"""

from abc import ABC
from abc import abstractmethod


class BaseService(ABC):

    """
    Base contract that every ArgusNet service must implement.
    """

    @property
    @abstractmethod
    def key(self) -> str:

        """
        Unique key used to select the service from the menu.
        Example: "1", "scan", etc...
        """

        pass


    @property
    @abstractmethod
    def name(self) -> str:

        """
        Human-readable service name displayed in the menu.
        """

        pass


    @abstractmethod
    def run(self) -> None:

        """
        Entry point for the service execution.
        """

        pass

