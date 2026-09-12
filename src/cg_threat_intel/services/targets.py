import ipaddress
import socket
from urllib.parse import urlparse


class TargetValidationError(ValueError):
    pass


def validate_public_https_target(url: str) -> str:
    """Allow only public HTTPS targets; resolve before scanning to prevent SSRF."""

    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise TargetValidationError("Targets must be public HTTPS URLs without embedded credentials.")
    if parsed.port not in (None, 443):
        raise TargetValidationError("Only the standard HTTPS port is supported.")
    try:
        addresses = {entry[4][0] for entry in socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)}
    except socket.gaierror as error:
        raise TargetValidationError("Target hostname could not be resolved.") from error
    if not addresses:
        raise TargetValidationError("Target hostname did not resolve to an address.")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise TargetValidationError("Targets resolving to private or reserved addresses are not permitted.")
    return parsed.geturl()
