import os

import fastapi

from app.domain.worker import run


class PublicService:
    pass


class _PrivateService:
    pass


def public_function():
    os.system("never executed")


def _private_function():
    return run

