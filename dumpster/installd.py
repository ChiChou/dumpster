from __future__ import annotations

import logging
from contextlib import contextmanager
from importlib.resources import files
from typing import Iterator

import frida

FRIDA_DEVICE_TIMEOUT_SECONDS = 10


def _on_message(message: dict, data: bytes | None) -> None:
    if message.get("type") == "error":
        logging.error("installd hook error: %s", message.get("stack", message))
    elif message.get("type") == "log":
        logging.debug("installd hook: %s", message.get("payload", ""))


@contextmanager
def installd_hook(udid: str | None = None) -> Iterator[None]:
    """Attach to installd and keep the bundled Frida hook loaded."""
    logging.info("attaching Frida installd hook")
    if udid:
        device = frida.get_device(udid, timeout=FRIDA_DEVICE_TIMEOUT_SECONDS)
    else:
        device = frida.get_usb_device(timeout=FRIDA_DEVICE_TIMEOUT_SECONDS)

    session = device.attach("installd")
    try:
        source = (
            files("dumpster")
            .joinpath("installd.js")
            .read_text(encoding="utf-8")
        )
        script = session.create_script(source)
        script.on("message", _on_message)
        script.load()
        try:
            yield
        finally:
            logging.info("unloading Frida installd hook")
            script.unload()
    finally:
        session.detach()
