"""
Investigation graph + timeline endpoints.
Returns D3-compatible graph data (nodes + edges) and timeline events.
Also computes graph analytics: degree centrality, betweenness (approximation),
cluster detection (connected components), and key entity identification.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from database import get_db
from models import Investigation, Evidence, EnrichedEntity, User
from api.deps import get_current_user
from collections import defaultdict, deque

router = APIRouter(prefix="/graph", tags=["graph"])


def _compute_degree_centrality(nodes: list[dict], edges: list[dict]) -> dict[str, float]:
    """Compute degree centrality for each node = degree / (N-1)."""
    n = len(nodes)
    if n <= 1:
        return {node["id"]: 0.0 for node in nodes}
    degree = defaultdict(int)
    for e in edges:
        degree[e["source"]] += 1
        degree[e["target"]] += 1
    return {node_id: deg / (n - 1) for node_id, deg in degree.items()}


def _detect_clusters(nodes: list[dict], edges: list[dict]) -> list[list[str]]:
    """Detect connected components via BFS. Returns list of node-id lists."""
    if not nodes:
        return []
    adj: dict[str, set[str]] = defaultdict(set)
    for e in edges:
        adj[e["source"]].add(e["target"])
        adj[e["target"]].add(e["source"])

    visited: set[str] = set()
    clusters: list[list[str]] = []
    for node in nodes:
        nid = node["id"]
        if nid in visited:
            continue
        # BFS
        cluster: list[str] = []
        queue = deque([nid])
        visited.add(nid)
        while queue:
            cur = queue.popleft()
            cluster.append(cur)
            for neighbor in adj.get(cur, ()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        clusters.append(cluster)
    # Sort clusters by size descending
    clusters.sort(key=len, reverse=True)
    return clusters


def _identify_hubs(centrality: dict[str, float], threshold: float = 0.5) -> list[str]:
    """Nodes with centrality above threshold are 'hubs'."""
    return sorted(
        [nid for nid, c in centrality.items() if c >= threshold],
        key=lambda nid: centrality[nid],
        reverse=True,
    )


def _shortest_paths(node_id: str, adj: dict[str, set[str]]) -> dict[str, int]:
    """BFS shortest path distances from node_id."""
    dists = {node_id: 0}
    queue = deque([node_id])
    while queue:
        cur = queue.popleft()
        for nxt in adj.get(cur, ()):
            if nxt not in dists:
                dists[nxt] = dists[cur] + 1
                queue.append(nxt)
    return dists


def _approx_betweenness(nodes: list[dict], edges: list[dict]) -> dict[str, float]:
    """
    Approximate betweenness centrality — for each pair (s, t), count how many
    shortest paths pass through each intermediate node. We use BFS from each
    node (O(N * (V+E))) which is fine for small investigation graphs (<500 nodes).
    """
    n = len(nodes)
    if n <= 2:
        return {node["id"]: 0.0 for node in nodes}

    adj: dict[str, set[str]] = defaultdict(set)
    for e in edges:
        adj[e["source"]].add(e["target"])
        adj[e["target"]].add(e["source"])

    betweenness: dict[str, float] = defaultdict(float)
    for source in nodes:
        sid = source["id"]
        dists = _shortest_paths(sid, adj)
        # For each target != source, find shortest path and increment intermediates
        for target_id, d in dists.items():
            if target_id == sid or d <= 1:
                continue
            # Walk back from target to source via neighbors with d-1
            # We pick the first path (approximation; full Brandes is O(N*M))
            stack = [target_id]
            visited = {target_id}
            path = [target_id]
            while stack:
                cur = stack[-1]
                if cur == sid:
                    break
                next_step = None
                for neighbor in adj.get(cur, ()):
                    if neighbor in visited:
                        continue
                    if dists.get(neighbor, float("inf")) == dists[cur] - 1:
                        next_step = neighbor
                        break
                if next_step is None:
                    stack.pop()
                    if stack:
                        path.pop()
                    continue
                stack.append(next_step)
                visited.add(next_step)
                path.append(next_step)
            # Intermediate nodes on the path get +1
            for intermediate in path[1:-1]:
                betweenness[intermediate] += 1.0

    # Normalize: divide by ((n-1)*(n-2)/2) for undirected graphs
    norm = max((n - 1) * (n - 2) / 2, 1)
    return {nid: b / norm for nid, b in betweenness.items()}


@router.get("/{inv_id}")
async def get_investigation_graph(inv_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Return D3 force-directed graph: nodes + edges + analytics."""
    result = await db.execute(
        select(Investigation).where(Investigation.id == inv_id, Investigation.user_id == user.id)
    )
    inv = result.scalar_one_or_none()
    if not inv:
        from fastapi import HTTPException
        raise HTTPException(404, "Investigation not found")

    ev_result = await db.execute(select(Evidence).where(Evidence.investigation_id == inv_id))
    evidence = ev_result.scalars().all()

    ent_result = await db.execute(select(EnrichedEntity).where(EnrichedEntity.investigation_id == inv_id))
    entities = ent_result.scalars().all()

    nodes = []
    edges = []
    node_ids = set()

    def _add_node(node_id: str, label: str, ntype: str, group: int, data: dict | None = None):
        if node_id in node_ids:
            return
        node_ids.add(node_id)
        nodes.append({
            "id": node_id, "label": label, "type": ntype, "group": group,
            "data": data or {},
        })

    target_id = f"target:{inv.target}"
    _add_node(target_id, inv.target, "target", 0, {"target_type": inv.target_type})

    for ev in evidence:
        plugin_id = f"plugin:{ev.plugin_name}"
        _add_node(plugin_id, ev.plugin_name, "plugin", 1,
                  {"success": "error" not in (ev.data or {})})
        edges.append({"source": target_id, "target": plugin_id, "label": "collected_by"})
        for ent in entities:
            if ent.source_plugin == ev.plugin_name:
                ent_id = f"entity:{ent.entity_type}:{ent.value}"
                _add_node(ent_id, ent.value[:60], ent.entity_type, 2,
                          {"confidence": ent.confidence, "context": ent.context})
                edges.append({"source": plugin_id, "target": ent_id, "label": "extracted"})

    # Analytics
    centrality = _compute_degree_centrality(nodes, edges)
    clusters = _detect_clusters(nodes, edges)
    hubs = _identify_hubs(centrality, threshold=0.3)
    betweenness = _approx_betweenness(nodes, edges) if len(nodes) <= 100 else {}

    return {
        "nodes": nodes, "edges": edges,
        "target": inv.target, "target_type": inv.target_type,
        "analytics": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "cluster_count": len(clusters),
            "largest_cluster_size": len(clusters[0]) if clusters else 0,
            "degree_centrality": centrality,
            "betweenness_centrality": betweenness,
            "hubs": hubs,
            "top_5_central": sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:5],
        },
    }


@router.get("/{inv_id}/timeline")
async def get_investigation_timeline(inv_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Return timeline events for an investigation."""
    result = await db.execute(
        select(Investigation).where(Investigation.id == inv_id, Investigation.user_id == user.id)
    )
    inv = result.scalar_one_or_none()
    if not inv:
        from fastapi import HTTPException
        raise HTTPException(404, "Investigation not found")

    ev_result = await db.execute(select(Evidence).where(Evidence.investigation_id == inv_id))
    evidence = ev_result.scalars().all()

    events = []

    events.append({
        "timestamp": inv.created_at.isoformat(),
        "type": "investigation_start",
        "title": f"Investigation started: {inv.target}",
        "description": f"Target type: {inv.target_type}",
        "icon": "🦅",
    })

    for ev in evidence:
        events.append({
            "timestamp": ev.collected_at.isoformat(),
            "type": "evidence_collected",
            "title": f"{ev.plugin_name} data collected",
            "description": (str(ev.data)[:200] if ev.data else "")[:200],
            "icon": "📦",
            "plugin": ev.plugin_name,
        })

    for ev in evidence:
        d = ev.data or {}
        if ev.plugin_name == "breach" and d.get("breach_dates"):
            for dt in (d.get("breach_dates") or [])[:10]:
                events.append({
                    "timestamp": dt if isinstance(dt, str) else str(dt),
                    "type": "breach_event",
                    "title": f"Breach event: {ev.plugin_name}",
                    "description": f"Found via {ev.plugin_name}",
                    "icon": "🔓",
                })
        if ev.plugin_name == "wayback" and d.get("snapshots"):
            for snap in (d.get("snapshots") or [])[:5]:
                ts = snap.get("timestamp") if isinstance(snap, dict) else None
                if ts:
                    events.append({
                        "timestamp": ts,
                        "type": "wayback_snapshot",
                        "title": "Wayback Machine snapshot",
                        "description": snap.get("url", "") if isinstance(snap, dict) else str(snap),
                        "icon": "📚",
                    })
        if ev.plugin_name == "certs" and d.get("certificates"):
            for cert in (d.get("certificates") or [])[:5]:
                ts = cert.get("not_before") if isinstance(cert, dict) else None
                if ts:
                    events.append({
                        "timestamp": ts,
                        "type": "cert_issued",
                        "title": "Certificate issued",
                        "description": cert.get("common_name", "") if isinstance(cert, dict) else "",
                        "icon": "🔐",
                    })

    def _sort_key(e):
        ts = e.get("timestamp", "")
        try:
            return ts.ljust(32)
        except Exception:
            return ""
    events.sort(key=_sort_key)

    if inv.completed_at:
        events.append({
            "timestamp": inv.completed_at.isoformat(),
            "type": "investigation_complete",
            "title": "Investigation completed",
            "description": inv.summary[:200] if inv.summary else "",
            "icon": "✅",
        })

    return {"events": events, "target": inv.target}
