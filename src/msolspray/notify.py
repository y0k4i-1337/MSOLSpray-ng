import requests

from msolspray.utils import print_error

class SlackWebhook:
    """Helper class for sending posts to Slack using webhooks."""

    def __init__(self, webhook_url):
        self.webhook_url = webhook_url

    # Post a simple update to slack
    def post(self, text):
        block = f"```\n{text}\n```"
        payload = {
            "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": block}}]
        }
        status = self.__post_payload(payload)
        return status

    # Post a json payload to slack webhook URL
    def __post_payload(self, payload):
        response = requests.post(self.webhook_url, json=payload, timeout=4)
        if response.status_code != 200:
            print_error("Could not send notification to Slack")
            return False
        return True


def notify(webhook, text):
    """Send notifications using Webhooks.

    Args:
        webhook (str): Webhook endpoint
        text (str): Text to be sent
    """
    notifier = SlackWebhook(webhook)
    try:
        notifier.post(text)
    except BaseException:
        pass
