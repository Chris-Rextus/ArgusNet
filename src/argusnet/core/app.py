# src/argusnet/core/app.py

"""
Core application logic for ArgusNet

Defines the interactive terminal application.
"""

import os
from typing import Optional

from argusnet.core.registry import ServiceRegistry


class ArgusNetApp:

    """
    Main interactive application container.
    """

    def __init__(self, registry: ServiceRegistry) -> None:
        self.registry = registry

    def run(self) -> None:
        
        """
        Starts the interactive application loop.
        """

        while True:

            self._clear_terminal()
            self._print_header()
            self._print_menu()

            choice = input("\nSelect a service or ('q' to quit):").strip()

            if choice.lower() in {"q", "quit", "exit"}:
                print("Exiting ArgusNet.")
                break

            service = self.registry.get_service(choice)

            if service is None:
                input("\nInvalid selection. Press Enter to continue...")
                continue

            self._clear_terminal()
            service.run()

            input("\nPress Enter to return to main menu...")

    
    def _print_header(self) -> None:
        print("=" * 50)
        print("ArgusNet - Network Diagnostics Toolkit")
        print("=" * 50)

    
    def _print_menu(self) -> None:
        services = self.registry.list_services()
        for key, service in services.items():
            print(f"[{key}] {service.name}")

    
    @staticmethod
    def _clear_terminal() -> None:
        os.system("cls" if os.name == "nt" else "clear")


def create_app() -> ArgusNetApp:

    """
    Application Factory
    """

    registry = ServiceRegistry()
    registry.load_services()

    return ArgusNetApp(registry)