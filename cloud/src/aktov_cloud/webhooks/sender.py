"""Webhook delivery — fire-and-forget alert notifications.

Phase 0: asyncio.create_task, no queue.  Supports generic webhook and Slack
incoming webhook (Block Kit format).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aktov_cloud.config import settings
from aktov_cloud.models.alert import Alert
from aktov_cloud.models.notification_channel import NotificationChannel

logger = logging.getLogger(__name__)


def _format_generic_webhook(alert: Alert) -> dict[str, Any]:
    """Format an alert as a plain JSON payload for generic webhooks."""
    return {
        "alert_id": str(alert.id),
        "org_id": str(alert.org_id),
        "trace_id": str(alert.trace_id),
        "agent_id": str(alert.agent_id),
        "rule_id": str(alert.rule_id),
        "severity": alert.severity,
        "category": alert.category,
        "title": alert.title,
        "description": alert.description,
        "context": alert.context,
        "status": alert.status,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
    }


def _format_slack_block_kit(alert: Alert) -> dict[str, Any]:
    """Format an alert as a Slack Block Kit message for incoming webhooks."""
    severity_emoji = {
        "critical": ":rotating_light:",
        "high": ":warning:",
        "medium": ":large_yellow_circle:",
        "low": ":information_source:",
        "info": ":speech_balloon:",
    }
    emoji = severity_emoji.get(alert.severity, ":bell:")

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} Aktov Alert - {alert.severity.upper()}",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{alert.title}*\n{alert.description or ''}",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Category:*\n{alert.category}"},
                {"type": "mrkdwn", "text": f"*Severity:*\n{alert.severity}"},
                {"type": "mrkdwn", "text": f"*Trace:*\n`{alert.trace_id}`"},
                {"type": "mrkdwn", "text": f"*Alert ID:*\n`{alert.id}`"},
            ],
        },
    ]

    return {"blocks": blocks}


async def send_webhook(
    url: str,
    payload: dict[str, Any],
    timeout: int | None = None,
) -> bool:
    """POST a JSON payload to a webhook URL.

    Returns True on success (2xx), False otherwise.  Never raises — failures
    are logged and swallowed because webhook delivery is fire-and-forget.
    """
    _timeout = timeout or settings.webhook_timeout_seconds
    try:
        async with httpx.AsyncClient(timeout=_timeout) as client:
            resp = await client.post(url, json=payload)
            if resp.is_success:
                logger.info("Webhook delivered to %s (status=%d)", url, resp.status_code)
                return True
            else:
                logger.warning(
                    "Webhook delivery failed to %s (status=%d body=%s)",
                    url,
                    resp.status_code,
                    resp.text[:200],
                )
                return False
    except Exception:
        logger.exception("Webhook delivery error for %s", url)
        return False


async def deliver_alerts(
    alerts: list[Alert],
    org_id: uuid.UUID,
    db: AsyncSession,
) -> None:
    """Send alerts to all enabled notification channels for the org.

    This function is intended to be called via ``asyncio.create_task`` so it
    runs in the background without blocking the HTTP response.
    """
    result = await db.execute(
        select(NotificationChannel).where(
            NotificationChannel.org_id == org_id,
            NotificationChannel.enabled.is_(True),
        )
    )
    channels = result.scalars().all()

    if not channels:
        return

    for alert in alerts:
        for channel in channels:
            if channel.channel_type == "slack":
                payload = _format_slack_block_kit(alert)
            else:
                # Generic webhook and email-webhook hybrid
                payload = _format_generic_webhook(alert)

            url = (channel.config or {}).get("url")
            if not url:
                logger.warning(
                    "Notification channel %s has no URL configured, skipping.",
                    channel.id,
                )
                continue

            await send_webhook(url, payload)
