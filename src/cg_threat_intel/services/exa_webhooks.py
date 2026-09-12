import hashlib
import hmac


class WebhookSignatureError(ValueError):
    pass


def verify_exa_signature(*, body: bytes, signature_header: str | None, secret: str) -> None:
    """Verify Exa's timestamped HMAC-SHA256 webhook signature."""

    if not signature_header:
        raise WebhookSignatureError("Missing Exa-Signature header.")
    try:
        components = dict(item.split("=", maxsplit=1) for item in signature_header.split(","))
        timestamp = components["t"]
        provided_signature = components["v1"]
    except (KeyError, ValueError) as error:
        raise WebhookSignatureError("Malformed Exa-Signature header.") from error

    signed_payload = timestamp.encode() + b"." + body
    expected_signature = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_signature, provided_signature):
        raise WebhookSignatureError("Invalid Exa webhook signature.")
