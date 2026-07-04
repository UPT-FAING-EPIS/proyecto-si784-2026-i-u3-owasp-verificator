"""Configuración de entorno para Behave."""
import os
os.environ["APP_ENV"] = "test"

from fastapi.testclient import TestClient
from app.main import app
from app.store import scan_store


def before_scenario(context, scenario):
    scan_store.clear()
    context.client = TestClient(app)
    context.response = None
    context.scan = None


def after_scenario(context, scenario):
    scan_store.clear()
