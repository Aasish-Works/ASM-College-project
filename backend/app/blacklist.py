from __future__ import annotations

from fnmatch import fnmatch
import ipaddress
from urllib.parse import urlparse

from .models import BlacklistEntry
from .pipeline import PipelineAsset


def _match_pattern(asset: PipelineAsset, entry: BlacklistEntry) -> bool:
    raw_target = asset.host or asset.url or ""
    if asset.url and "://" in asset.url:
        parsed = urlparse(asset.url)
        raw_target = parsed.hostname or raw_target
    target = raw_target.split(":")[0] if raw_target else raw_target
    if entry.pattern_type == "exact":
        return target.lower() == entry.pattern.lower()
    if entry.pattern_type == "cidr":
        try:
            ip = ipaddress.ip_address(target)
            return ip in ipaddress.ip_network(entry.pattern, strict=False)
        except ValueError:
            return False
    return fnmatch(target.lower(), entry.pattern.lower())


def filter_blacklisted(assets: list[PipelineAsset], entries: list[BlacklistEntry]) -> list[PipelineAsset]:
    if not entries:
        return assets
    allowed = []
    for asset in assets:
        if any(_match_pattern(asset, entry) for entry in entries):
            continue
        allowed.append(asset)
    return allowed
