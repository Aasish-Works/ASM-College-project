from __future__ import annotations

import json
from collections import defaultdict, deque

from sqlalchemy.orm import Session

from .models import Asset, AssetRelationship, Vulnerability


def build_asset_graph(db: Session, target_id: int) -> dict[str, list[dict[str, object]]]:
    assets = db.query(Asset).filter(Asset.target_id == target_id).all()
    relationships = db.query(AssetRelationship).filter(AssetRelationship.target_id == target_id).all()

    vuln_scores: dict[int, list[float]] = defaultdict(list)
    for vulnerability in db.query(Vulnerability).filter(Vulnerability.target_id == target_id).all():
        if vulnerability.asset_id:
            vuln_scores[vulnerability.asset_id].append(float(vulnerability.risk_score or 0.0))

    nodes = []
    for asset in assets:
        asset_score = max(vuln_scores.get(asset.id, [float(asset.risk_score or 0.0)]))
        nodes.append(
            {
                "id": asset.id,
                "label": asset.value,
                "kind": asset.kind,
                "classification": asset.classification,
                "exposure": asset.exposure,
                "sensitivity": asset.sensitivity,
                "risk_score": round(asset_score, 2),
            }
        )

    edges = [
        {
            "id": relation.id,
            "source": relation.source_asset_id,
            "target": relation.target_asset_id,
            "relation": relation.relation,
            "confidence": relation.confidence,
            "reason": relation.reason,
        }
        for relation in relationships
    ]
    return {"nodes": nodes, "edges": edges}


def _build_adjacency(edges: list[dict[str, object]]) -> dict[int, list[tuple[int, dict[str, object]]]]:
    adjacency: dict[int, list[tuple[int, dict[str, object]]]] = defaultdict(list)
    for edge in edges:
        source = int(edge["source"])
        target = int(edge["target"])
        adjacency[source].append((target, edge))
        adjacency[target].append((source, edge))
    return adjacency


def _entry_nodes(nodes: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        node
        for node in nodes
        if node.get("exposure") in {"external", "public", "api", "cloud"}
        or node.get("classification") in {"external_asm", "api_attack_surface", "cloud_asm"}
    ]


def _goal_nodes(nodes: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        node
        for node in nodes
        if node.get("sensitivity") in {"high", "critical"}
        or node.get("risk_score", 0.0) >= 70
        or node.get("classification") in {"cloud_asm", "internal_asm"}
    ]


def _path_score(node_lookup: dict[int, dict[str, object]], path: list[int]) -> float:
    if not path:
        return 0.0
    base = sum(float(node_lookup[node].get("risk_score", 0.0)) for node in path) / len(path)
    exposed_bonus = 10.0 if node_lookup[path[0]].get("exposure") in {"external", "public"} else 0.0
    crown_bonus = 12.0 if node_lookup[path[-1]].get("sensitivity") in {"high", "critical"} else 0.0
    depth_bonus = min(len(path) * 2.5, 15.0)
    return round(min(base + exposed_bonus + crown_bonus + depth_bonus, 100.0), 2)


def simulate_attack_paths(db: Session, target_id: int, limit: int = 8) -> list[dict[str, object]]:
    graph = build_asset_graph(db, target_id)
    nodes = graph["nodes"]
    edges = graph["edges"]
    if not nodes or not edges:
        return []

    adjacency = _build_adjacency(edges)
    node_lookup = {int(node["id"]): node for node in nodes}
    entries = _entry_nodes(nodes)
    goals = {int(node["id"]) for node in _goal_nodes(nodes)}
    if not entries or not goals:
        return []

    discovered_paths: list[dict[str, object]] = []
    seen_paths: set[tuple[int, ...]] = set()

    for entry in entries:
        entry_id = int(entry["id"])
        queue: deque[tuple[int, list[int], list[dict[str, object]]]] = deque([(entry_id, [entry_id], [])])
        while queue and len(discovered_paths) < limit * 3:
            current, path, traversed = queue.popleft()
            if current in goals and len(path) > 1:
                path_key = tuple(path)
                if path_key not in seen_paths:
                    seen_paths.add(path_key)
                    discovered_paths.append(
                        {
                            "entry": node_lookup[path[0]],
                            "goal": node_lookup[path[-1]],
                            "path": [node_lookup[node_id] for node_id in path],
                            "edges": traversed,
                            "score": _path_score(node_lookup, path),
                            "summary": " -> ".join(node_lookup[node_id]["label"] for node_id in path),
                        }
                    )
                continue
            if len(path) >= 5:
                continue
            for neighbor, edge in adjacency.get(current, []):
                if neighbor in path:
                    continue
                queue.append((neighbor, path + [neighbor], traversed + [edge]))

    discovered_paths.sort(key=lambda item: item["score"], reverse=True)
    return discovered_paths[:limit]


def export_graph_snapshot(db: Session, target_id: int) -> str:
    return json.dumps(build_asset_graph(db, target_id), default=str)
