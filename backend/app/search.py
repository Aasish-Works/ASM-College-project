from __future__ import annotations

import re
from typing import Iterable

from .models import Asset


OPERATORS = ["==", "!=", "~"]
FIELD_MAP = {
    "host": "host",
    "url": "url",
    "title": "title",
    "tech": "tech",
    "status": "status_code",
    "body": "body_snippet",
    "header": "header_snippet",
}


def _split_groups(query: str) -> list[list[str]]:
    or_groups = [grp.strip() for grp in query.split("||") if grp.strip()]
    return [[part.strip() for part in grp.split("&&") if part.strip()] for grp in or_groups]


def _parse_condition(condition: str) -> tuple[str | None, str | None, str | None]:
    for op in OPERATORS:
        if op in condition:
            field, value = condition.split(op, 1)
            return field.strip(), op, value.strip().strip('"').strip("'")
    return None, None, condition.strip().strip('"').strip("'")


def _match_value(field_value: object, op: str, value: str) -> bool:
    if field_value is None:
        return False
    field_str = str(field_value)
    if op == "==":
        return field_str.lower() == value.lower()
    if op == "!=":
        return field_str.lower() != value.lower()
    return value.lower() in field_str.lower()


def _match_asset(asset: Asset, field: str | None, op: str | None, value: str) -> bool:
    if field is None:
        haystack = " ".join(
            str(getattr(asset, attr) or "") for attr in FIELD_MAP.values()
        ).lower()
        return value.lower() in haystack
    mapped = FIELD_MAP.get(field)
    if not mapped:
        return False
    return _match_value(getattr(asset, mapped), op or "~", value)


def filter_assets(assets: Iterable[Asset], query: str) -> list[Asset]:
    if not query:
        return list(assets)
    groups = _split_groups(query)
    matched = []
    for asset in assets:
        for group in groups:
            if all(_match_asset(asset, *_parse_condition(cond)) for cond in group):
                matched.append(asset)
                break
    return matched
