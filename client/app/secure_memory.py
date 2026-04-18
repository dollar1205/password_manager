from __future__ import annotations

import atexit
import ctypes
import hmac
import os
import secrets
import signal
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager

_emergency_wipe_callbacks: list[Callable[[], None]] = []
_emergency_wipe_lock = threading.Lock()
_emergency_handlers_installed = False


def buffer_from_text(text: str | None) -> bytearray:
    if not text:
        return bytearray()
    buffer = bytearray(text.encode("utf-8"))
    text = None
    return buffer


def compare_buffers(left: bytearray, right: bytearray) -> bool:
    return hmac.compare_digest(left, right)


def materialize_secret_text(buffer: bytearray | None) -> str:
    if not buffer:
        return ""
    return buffer.decode("utf-8")


@contextmanager
def temporary_secret_text(buffer: bytearray | None) -> Iterator[str]:
    text = materialize_secret_text(buffer)
    try:
        yield text
    finally:
        text = None


def register_emergency_wipe(callback: Callable[[], None]) -> None:
    with _emergency_wipe_lock:
        if callback not in _emergency_wipe_callbacks:
            _emergency_wipe_callbacks.append(callback)


def unregister_emergency_wipe(callback: Callable[[], None]) -> None:
    with _emergency_wipe_lock:
        if callback in _emergency_wipe_callbacks:
            _emergency_wipe_callbacks.remove(callback)


def run_emergency_wipe() -> None:
    with _emergency_wipe_lock:
        callbacks = tuple(reversed(_emergency_wipe_callbacks))

    for callback in callbacks:
        try:
            callback()
        except Exception:
            continue


def _chain_signal_handler(previous_handler, signum: int, frame) -> None:
    if previous_handler in (None, signal.SIG_DFL):
        raise SystemExit(128 + signum)

    if previous_handler is signal.SIG_IGN:
        raise SystemExit(0)

    if callable(previous_handler):
        previous_handler(signum, frame)
        return

    raise SystemExit(128 + signum)


def install_emergency_wipe_handlers() -> None:
    global _emergency_handlers_installed

    with _emergency_wipe_lock:
        if _emergency_handlers_installed:
            return
        _emergency_handlers_installed = True

    atexit.register(run_emergency_wipe)
    previous_excepthook = sys.excepthook

    def emergency_excepthook(exc_type, exc_value, traceback) -> None:
        try:
            run_emergency_wipe()
        finally:
            previous_excepthook(exc_type, exc_value, traceback)

    sys.excepthook = emergency_excepthook

    for signal_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if not hasattr(signal, signal_name):
            continue

        signum = getattr(signal, signal_name)
        previous_handler = signal.getsignal(signum)

        def emergency_signal_handler(received_signum, frame, *, _previous=previous_handler) -> None:
            try:
                run_emergency_wipe()
            finally:
                _chain_signal_handler(_previous, received_signum, frame)

        signal.signal(signum, emergency_signal_handler)


def try_lock_bytearray(buffer: bytearray | None) -> bool:
    if buffer is None or not buffer:
        return False

    try:
        address = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
        size = len(buffer)
    except (TypeError, ValueError):
        return False

    try:
        if os.name == "nt":
            return bool(ctypes.windll.kernel32.VirtualLock(ctypes.c_void_p(address), ctypes.c_size_t(size)))

        libc = ctypes.CDLL(None)
        return libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(size)) == 0
    except Exception:
        return False


def try_unlock_bytearray(buffer: bytearray | None) -> bool:
    if buffer is None or not buffer:
        return False

    try:
        address = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
        size = len(buffer)
    except (TypeError, ValueError):
        return False

    try:
        if os.name == "nt":
            return bool(ctypes.windll.kernel32.VirtualUnlock(ctypes.c_void_p(address), ctypes.c_size_t(size)))

        libc = ctypes.CDLL(None)
        return libc.munlock(ctypes.c_void_p(address), ctypes.c_size_t(size)) == 0
    except Exception:
        return False


def _fill_pattern(buffer: bytearray, value: int) -> None:
    for index in range(len(buffer)):
        buffer[index] = value


def _fill_random(buffer: bytearray) -> None:
    if not buffer:
        return
    buffer[:] = os.urandom(len(buffer))


def _jitter_delay() -> None:
    delay_ticks = secrets.randbelow(5)
    if delay_ticks:
        time.sleep(delay_ticks / 10_000.0)


def wipe_bytearray(buffer: bytearray | None) -> None:
    if buffer is None:
        return
    if not buffer:
        try_unlock_bytearray(buffer)
        return

    _fill_random(buffer)
    _jitter_delay()

    for pattern in (secrets.randbelow(256), 0xA5, secrets.randbelow(256), 0x5A, 0x00):
        _fill_pattern(buffer, pattern)
        if pattern != 0x00:
            _jitter_delay()

    try:
        raw_buffer = (ctypes.c_char * len(buffer)).from_buffer(buffer)
        ctypes.memset(ctypes.addressof(raw_buffer), 0, len(buffer))
    except (TypeError, ValueError):
        pass
    finally:
        try_unlock_bytearray(buffer)


def wipe_many(*buffers: bytearray | None) -> None:
    for buffer in buffers:
        wipe_bytearray(buffer)


@contextmanager
def sensitive_text_buffer(text: str | None) -> Iterator[bytearray]:
    buffer = buffer_from_text(text)
    try_lock_bytearray(buffer)
    text = None
    try:
        yield buffer
    finally:
        wipe_bytearray(buffer)
