"""
engine/graph_builder.py
=======================
Build entity-relationship graphs from session logs.

Constructs a networkx DiGraph where nodes are entities (IPs, users, hosts)
and edges represent events between them. Exportable to JSON for frontend
visualization with react-force-graph-2d.
"""

import ipaddress
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx
import pandas as pd


def build_session_graph(
    df: pd.DataFrame,
    alerts: List[Dict[str, Any]],
    alert_id_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build an entity-relationship graph from session logs and alerts.

    If alert_id_filter is provided, return a 2-hop subgraph around that alert's entities.
    Otherwise return the full session graph.

    Returns a JSON-serializable dict: {nodes, edges, stats}
    """
    if df.empty:
        return {"nodes": [], "edges": [], "stats": {}}

    # Step 1: Build full graph from DataFrame
    G = nx.DiGraph()

    # Collect entities
    ips: Set[str] = set()
    users: Set[str] = set()
    hosts: Set[str] = set()

    for _, row in df.iterrows():
        # Source IP
        if "source_ip" in row and pd.notna(row["source_ip"]):
            source_ip = str(row["source_ip"])
            ips.add(source_ip)
            G.add_node(source_ip, node_type="ip")

        # Dest IP (could be a host)
        if "dest_ip" in row and pd.notna(row["dest_ip"]):
            dest_ip = str(row["dest_ip"])
            ips.add(dest_ip)
            host_type = "external_ip" if _is_external_ip(dest_ip) else "ip"
            G.add_node(dest_ip, node_type=host_type)

        # User
        if "user" in row and pd.notna(row["user"]):
            user = str(row["user"])
            users.add(user)
            G.add_node(user, node_type="user")

        # Create edges
        if "source_ip" in row and "dest_ip" in row:
            source = str(row["source_ip"])
            dest = str(row["dest_ip"])
            event_type = row.get("event_type", "unknown") if "event_type" in row else "unknown"

            if pd.notna(source) and pd.notna(dest):
                if G.has_edge(source, dest):
                    # Increment weight
                    G[source][dest]["weight"] += 1
                    G[source][dest]["event_types"].add(event_type)
                else:
                    G.add_edge(source, dest, weight=1, event_types={event_type})

        # User -> Dest IP edge
        if "user" in row and "dest_ip" in row:
            user = str(row["user"])
            dest = str(row["dest_ip"])

            if pd.notna(user) and pd.notna(dest):
                if G.has_edge(user, dest):
                    G[user][dest]["weight"] += 1
                else:
                    G.add_edge(user, dest, weight=1)

    # Step 2: Calculate node risk scores from alerts
    alert_entities: Dict[str, float] = {}  # entity_id -> count of alerts mentioning it
    entity_rules: Dict[str, Set[str]] = {}  # entity_id -> rule names
    entity_sev: Dict[str, str] = {}         # entity_id -> worst severity

    _SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    def _tag(entity_id: str, alert: Dict[str, Any]) -> None:
        alert_entities[entity_id] = alert_entities.get(entity_id, 0) + 1
        entity_rules.setdefault(entity_id, set()).add(
            alert.get("rule_name") or alert.get("rule_id") or "alert"
        )
        sev = str(alert.get("severity", "")).upper()
        if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(entity_sev.get(entity_id, ""), 0):
            entity_sev[entity_id] = sev

    for alert in alerts:
        if alert.get("source_ip"):
            _tag(alert["source_ip"], alert)
        if alert.get("dest_ip"):
            _tag(alert["dest_ip"], alert)
        if alert.get("user"):
            _tag(alert["user"], alert)

    # Step 3: If filtering to a specific alert's context, build subgraph
    if alert_id_filter:
        # Find the alert
        alert = next(
            (a for a in alerts if a.get("alert_id") == alert_id_filter), None
        )
        if alert:
            seed_nodes = set()
            if alert.get("source_ip"):
                seed_nodes.add(alert["source_ip"])
            if alert.get("dest_ip"):
                seed_nodes.add(alert["dest_ip"])
            if alert.get("user"):
                seed_nodes.add(alert["user"])

            # Get 2-hop neighbors
            subgraph_nodes = set(seed_nodes)
            for node in seed_nodes:
                if node in G:
                    subgraph_nodes.update(G.predecessors(node))
                    subgraph_nodes.update(G.successors(node))

            G = G.subgraph(subgraph_nodes).copy()

    # Step 4: Convert to JSON-serializable format
    nodes = []
    for node in G.nodes():
        node_data = G.nodes[node]
        node_type = node_data.get("node_type", "unknown")
        risk = alert_entities.get(node, 0)

        nodes.append(
            {
                "id": node,
                "type": node_type,
                "label": node,
                "risk_score": min(10.0, risk * 1.5),  # Scale up risk
                "event_count": risk,
                "in_alert": risk > 0,
                "severity": entity_sev.get(node),
                "alert_rules": sorted(entity_rules.get(node, set())),
            }
        )

    edges = []
    for source, dest, data in G.edges(data=True):
        edges.append(
            {
                "source": source,
                "target": dest,
                "event_type": ", ".join(
                    sorted(data.get("event_types", {"unknown"}))
                )[:30],  # Truncate
                "count": data.get("weight", 1),
                "weight": data.get("weight", 1),
            }
        )

    stats = {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "density": nx.density(G) if len(nodes) > 1 else 0.0,
    }

    return {"nodes": nodes, "edges": edges, "stats": stats}


def _is_external_ip(ip: str) -> bool:
    """Check if an IP is external (not RFC1918 / loopback / link-local)."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local)
    except (ValueError, TypeError):
        return False
