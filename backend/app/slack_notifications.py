import logging
import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import httpx

logger = logging.getLogger(__name__)


def send_slack_notification(
    title: str,
    message: str,
    color: str = "#36a64f",
) -> bool:
    """
    Send a notification through Slack Incoming Webhooks.
    Slack failures must never interrupt scan execution.
    """

    webhook_url = os.getenv("SLACK_WEBHOOK_URL", "").strip()

    if not webhook_url:
        logger.info("Slack notification skipped: webhook not configured.")
        return False

    if not webhook_url.startswith("https://hooks.slack.com/services/"):
        logger.warning("Slack notification skipped: invalid webhook configuration.")
        return False

    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": title[:150],
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": message[:2900],
                        },
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": "*ContainerShield AI*",
                            }
                        ],
                    },
                ],
            }
        ]
    }

    try:
        response = httpx.post(
            webhook_url,
            json=payload,
            timeout=5.0,
        )
        response.raise_for_status()

        logger.info("Slack notification sent: %s", title)
        return True

    except Exception as exc:
        logger.warning(
            "Slack notification failed (%s): %s",
            type(exc).__name__,
            str(exc).split(" for ")[0],
        )
        return False

def format_ist_timestamp(value=None) -> str:
    """Convert timestamps to Indian Standard Time."""

    if value is None:
        value = datetime.now(timezone.utc)

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.astimezone(
        ZoneInfo("Asia/Kolkata")
    ).strftime("%d %b %Y, %I:%M:%S %p IST")