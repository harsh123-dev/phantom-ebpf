import aiohttp
import json
import structlog
from typing import Any

log = structlog.get_logger(__name__)

class ApiDispatcher:
    def __init__(self, gateway_url: str, token: str):
        self.gateway_url = gateway_url.rstrip("/")
        self.token = token
        self.session = aiohttp.ClientSession(
            headers={"Authorization": f"Bearer {self.token}"}
        )

    async def dispatch_event(self, event_payload: dict[str, Any]) -> bool:
        url = f"{self.gateway_url}/api/v1/drift-events"
        try:
            async with self.session.post(url, json=event_payload) as response:
                if response.status in (200, 201, 202):
                    log.info("dispatcher.success", event_id=event_payload.get("event_id"))
                    return True
                else:
                    text = await response.text()
                    log.error("dispatcher.error", status=response.status, body=text)
                    return False
        except Exception as exc:
            log.exception("dispatcher.exception", error=str(exc))
            return False

    async def close(self):
        await self.session.close()
