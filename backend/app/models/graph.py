"""Authorization graph data model (networkx MultiDiGraph).

Node kinds:
  principal   user:<username>   - an acting identity (carries role, uid)
  role        role:<name>       - a role
  resource    report:<id>, user:<id>, admin:<path>, collection:<name>

Edge relations (edge attribute 'rel'):
  has_role    principal -> role
  owns        principal -> resource    (who OWNS)
  requested   principal -> resource    (who REQUESTED; observed by probing)

The graph fuses three evidence streams - identities/roles, ownership, and
observed access - so the policy layer can decide which observed requests are
not permitted. A MultiDiGraph is used because one principal can both OWN and
REQUEST the same resource (two parallel edges with different 'rel').
"""
import networkx as nx


class AuthorizationGraph:
    PRINCIPAL = "principal"
    ROLE = "role"
    RESOURCE = "resource"

    def __init__(self):
        self.g = nx.MultiDiGraph()

    def add_principal(self, username: str, role: str, uid=None) -> None:
        self.g.add_node(f"user:{username}", kind=self.PRINCIPAL,
                        username=username, role=role, uid=uid)
        self.g.add_node(f"role:{role}", kind=self.ROLE, role=role)
        self.g.add_edge(f"user:{username}", f"role:{role}", rel="has_role")

    def add_resource(self, resource_id: str, rtype: str, owner=None) -> None:
        if resource_id not in self.g:
            self.g.add_node(resource_id, kind=self.RESOURCE, rtype=rtype, owner=owner)
        if owner:
            self.g.add_edge(f"user:{owner}", resource_id, rel="owns")

    def add_request(self, username: str, resource_id: str, **attrs) -> None:
        self.g.add_edge(f"user:{username}", resource_id, rel="requested", **attrs)

    def role_of(self, username: str):
        return self.g.nodes.get(f"user:{username}", {}).get("role")

    def owner_of(self, resource_id: str):
        return self.g.nodes.get(resource_id, {}).get("owner")

    def requests(self):
        """Yield (username, resource_id, edge_data) for each observed request."""
        for u, v, data in self.g.edges(data=True):
            if data.get("rel") == "requested":
                yield self.g.nodes[u]["username"], v, data

    def summary(self) -> dict:
        kinds, rels = {}, {}
        for _, d in self.g.nodes(data=True):
            kinds[d.get("kind")] = kinds.get(d.get("kind"), 0) + 1
        for _, _, d in self.g.edges(data=True):
            rels[d.get("rel")] = rels.get(d.get("rel"), 0) + 1
        return {"nodes": kinds, "edges": rels}

    def to_dict(self) -> dict:
        """node-link JSON snapshot (consumed by the API/graph viz in later phases)."""
        return nx.node_link_data(self.g, edges="edges")
