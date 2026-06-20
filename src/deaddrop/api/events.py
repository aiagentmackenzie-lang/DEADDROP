"""In-process event bus — real WebSocket events for case lifecycle changes.

The previous TS WebSocket was an echo server (`{type:'ack'`). This bus lets the
engine publish real events (case created, evidence ingested, artifact added,
hunt hit, report generated) and the WebSocket endpoint subscribe per client.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import deque
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger(__name__)


class EventBus:
    """Async pub/sub for DEADDROP lifecycle events.

    A bounded history buffer lets a newly-connected client receive recent
    events before subscribing live (so the dashboard isn't blank on connect).
    """

    def __init__(self, history_size: int = 100) -> None:
        self._subscribers: list[asyncio.Queue[dict[str, Any]]] = []
        self._history: deque[dict[str, Any]] = deque(maxlen=history_size)
        self._lock = asyncio.Lock()
        # The running event loop, captured at API startup so sync route handlers
        # (which run in a worker thread) can schedule publishes onto the loop
        # via call_soon_threadsafe. None when no API server is running (pure CLI).
        self._loop: asyncio.AbstractEventLoop | None = None

    async def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        """Register a subscriber queue. Prefeeds recent history."""
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=1000)
        async with self._lock:
            self._subscribers.append(q)
            for event in self._history:
                # Prefeed without blocking; drop on overflow (client is slow)
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    break
        return q

    async def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        async with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    async def publish(self, event_type: str, payload: dict[str, Any]) -> None:
        """Publish an event to all live subscribers and record history."""
        event = {
            "type": event_type,
            "timestamp": datetime.now(UTC).isoformat(),
            "data": payload,
        }
        async with self._lock:
            self._history.append(event)
            for q in self._subscribers:
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    # Slow client — drop oldest and retry once
                    try:
                        q.get_nowait()
                        q.put_nowait(event)
                    except asyncio.QueueEmpty:
                        pass
        log.debug("event published: %s", event_type)

    def reset(self) -> None:
        """Clear history and subscribers (for tests / fresh start)."""
        self._history.clear()
        self._subscribers.clear()

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Capture the running event loop for cross-thread publish."""
        self._loop = loop

    def publish_sync(self, event_type: str, payload: dict[str, Any]) -> None:
        """Synchronous publish for use from sync engine code / route handlers.

        Route handlers run in FastAPI's threadpool, NOT on the event loop. To
        deliver to live WebSocket subscribers we must schedule onto the loop via
        `call_soon_threadsafe`. When no loop is bound (pure CLI use), we still
        record to history so the event is available to later subscribers.
        """
        if self._loop is not None and self._loop.is_running():
            # Cross-thread: schedule the async publish on the loop.
            self._loop.call_soon_threadsafe(
                lambda: asyncio.ensure_future(self.publish(event_type, payload))
            )
            return
        # No running loop — record to history directly.
        self._history.append({
            "type": event_type,
            "timestamp": datetime.now(UTC).isoformat(),
            "data": payload,
        })


# Module-level singleton — the engine and WebSocket both reach this.
bus = EventBus()


def emit(event_type: str, payload: dict[str, Any]) -> None:
    """Convenience: publish_sync to the global bus."""
    bus.publish_sync(event_type, payload)


def dumps(event: dict[str, Any]) -> str:
    """JSON-encode an event for WebSocket frames."""
    return json.dumps(event, default=str)
