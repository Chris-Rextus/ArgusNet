# src/argusnet/cli.py

"""
ArgusNet CLI Entry Point

This module is the executable boundary of the application.
It bootstraps the core application and starts the main loop.
"""

from argusnet.core.app import create_app


def main() -> None:

    """
    Application Entrypoint
    """

    app = create_app()
    app.run()

if __name__ == "__main__":
    main()