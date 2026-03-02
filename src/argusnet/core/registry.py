# src/argusnet/core/registry.py

"""
Service registry for ArgusNet.

Responsible for discovering and registering
available services dynamically.
"""

import pkgutil
import importlib
import argusnet.services
from typing import Dict, Optional

from argusnet.core.interfaces import BaseService


class ServiceRegistry:

    """
    Central registry that manages available services.
    """


    def __init__(self) -> None:
        self._services: Dict[str, BaseService] = {}


    def register(self, service: BaseService) -> None:

        """
        Registers a new service.
        """

        if service.key in self._services:
            raise ValueError(f"Service key '{service.key}' is already registered.")

        self._services[service.key] = service


    def get_service(self, key: str) -> Optional[BaseService]:
        return self._services.get(key)


    def list_services(self) -> Dict[str, BaseService]:
        return self._services


    def load_services(self) -> None:    

        """
        Automatically discover and load services
        from argusnet.services package.

        Supports:
        - Single-file services
        - Folder-based services
        """

        package = argusnet.services
        print("DEBUG: services path ->", package.__path__)

        for finder, name, ispkg in pkgutil.iter_modules(package.__path__):

            print("DEBUG: found module:", name, "is package:", ispkg)

            try:
                if ispkg:

                    # Folder-based service
                    module_path = f"{package.__name__}.{name}.service"
                    
                else:

                    # Single-file service
                    module_path = f"{package.__name__}.{name}"

                module = importlib.import_module(module_path)

                if hasattr(module, "service"):
                    service_instance = getattr(module, "service")

                    if isinstance(service_instance, BaseService):
                        self.register(service_instance)

            except Exception as e:
                print(f"[WARNING] Failed to load service '{name}': {e}")