"""Logfire setup with request attributes restricted to avoid recording user data."""

from typing import Any

import logfire
from fastapi import FastAPI
from starlette.requests import HTTPConnection

from app.config import LOGFIRE_TOKEN


def _safe_request_attributes(
    _: HTTPConnection, attributes: dict[str, Any]
) -> dict[str, Any]:
    """Keep validation locations and error types; drop query/body values."""
    return {
        "values": {},
        "errors": [
            {"loc": error.get("loc"), "type": error.get("type")}
            for error in attributes.get("errors", [])
        ],
    }


def instrument_app(app: FastAPI) -> None:
    """Configure local tracing and enable Logfire export when a token is present."""
    logfire.configure(
        service_name="signaldesk-api",
        token=LOGFIRE_TOKEN,
        send_to_logfire=bool(LOGFIRE_TOKEN),
        console=False,
    )
    logfire.instrument_fastapi(
        app,
        request_attributes_mapper=_safe_request_attributes,
    )
