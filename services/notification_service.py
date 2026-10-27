import requests
import logging
from datetime import datetime
from CTFd.models import db
from ..models.config import ContainerConfig

logger = logging.getLogger(__name__)

class NotificationService:
    def __init__(self):
        self.webhook_url = None
        # Cooldown registry for recurring infrastructure alerts
        # (checked every minute - without this, Discord would be spammed)
        self._last_alert = {}

    def notify_infra(self, key, title, message, fields=None, cooldown_minutes=15):
        """
        Send an infrastructure alert at most once per cooldown window.

        Args:
            key: Dedup key (e.g. 'docker_down', 'ports_low')
            title/message/fields: Same as send_alert
            cooldown_minutes: Minimum minutes between alerts with the same key
        """
        now = datetime.utcnow()
        last = self._last_alert.get(key)
        if last and (now - last).total_seconds() < cooldown_minutes * 60:
            return False
        sent = self.send_alert(title=title, message=message, color=0xff0000, fields=fields)
        if sent:
            self._last_alert[key] = now
        return sent

    def _get_webhook_url(self):
        return ContainerConfig.get('container_discord_webhook_url', '')

    def send_alert(self, title, message, color=0xff0000, fields=None):
        """
        Send an alert to Discord
        
        Args:
            title: Embed title
            message: Embed description
            color: Hex color integer (default red)
            fields: List of dicts {'name': str, 'value': str, 'inline': bool}
        """
        webhook_url = self._get_webhook_url()
        if not webhook_url:
            return False

        try:
            payload = {
                "embeds": [{
                    "title": title,
                    "description": message,
                    "color": color,
                    "fields": fields or []
                }]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=5)
            return response.status_code == 204
        except Exception as e:
            logger.error(f"Failed to send Discord notification: {e}")
            return False

    def notify_cheat(self, user, challenge, flag, owner):
        """Send cheat detection alert"""
        fields = [
            {"name": "User", "value": user.name if user else "Unknown", "inline": True},
            {"name": "Challenge", "value": challenge.name if challenge else "Unknown", "inline": True},
            {"name": "Flag Submitted", "value": f"`{flag}`", "inline": False},
            {"name": "Original Owner", "value": owner.name if owner else "Unknown", "inline": True},
            {"name": "Action Taken", "value": "User & Owner Banned", "inline": False}
        ]
        
        return self.send_alert(
            title="🚨 Cheating Detected!",
            message="A user submitted a flag belonging to another team/user.",
            color=0xff0000, # Red
            fields=fields
        )

    def notify_error(self, operation, error_msg):
        """Send system error alert"""
        fields = [
            {"name": "Operation", "value": operation, "inline": True},
            {"name": "Error", "value": f"```{error_msg}```", "inline": False}
        ]
        
        return self.send_alert(
            title="⚠️ Container System Error",
            message="An error occurred in the container system.",
            color=0xffa500, # Orange
            fields=fields
        )

    def send_test(self, webhook_url=None):
        """Send a simple test message"""
        url_to_use = webhook_url or self._get_webhook_url()
        return self._send_raw(
            url_to_use,
            title="✅ Connection Test",
            message="Your Discord Webhook is configured correctly!",
            color=0x00ff00 # Green
        )

    def send_demo_cheat(self, webhook_url=None):
        """Send a demo cheat alert"""
        url_to_use = webhook_url or self._get_webhook_url()
        fields = [
            {"name": "User", "value": "demo_hacker", "inline": True},
            {"name": "Challenge", "value": "Demo Challenge", "inline": True},
            {"name": "Flag Submitted", "value": "`CTF{demo_flag_hash}`", "inline": False},
            {"name": "Original Owner", "value": "innocent_victim", "inline": True},
            {"name": "Action Taken", "value": "User & Owner Banned", "inline": False}
        ]
        return self._send_raw(
            url_to_use,
            title="🚨 Cheating Detected! (DEMO)",
            message="This is a DEMO alert. No actual banning occurred.",
            color=0xff0000, # Red
            fields=fields
        )

    def send_demo_error(self, webhook_url=None):
        """Send a demo error alert"""
        url_to_use = webhook_url or self._get_webhook_url()
        fields = [
            {"name": "Operation", "value": "Container Provisioning", "inline": True},
            {"name": "Error", "value": "```DockerException: Connection refused```", "inline": False}
        ]
        return self._send_raw(
            url_to_use,
            title="⚠️ Plugin Error (DEMO)",
            message="This is a DEMO alert.",
            color=0xffa500, # Orange
            fields=fields
        )

    def _send_raw(self, url, title, message, color, fields=None):
        """Internal method to send to a specific URL"""
        if not url:
            return False
        
        try:
            payload = {
                "embeds": [{
                    "title": title,
                    "description": message,
                    "color": color,
                    "fields": fields or []
                }]
            }
            response = requests.post(url, json=payload, timeout=5)
            return response.status_code == 204
        except Exception as e:
            logger.error(f"Failed to send Discord notification: {e}")
            return False
