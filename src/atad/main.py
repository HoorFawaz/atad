# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Console entry point (`atad`)."""

from atad.cli.app import app


def run() -> None:
    app()


if __name__ == "__main__":
    run()
