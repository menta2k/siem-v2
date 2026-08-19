package group

// unionFind links identifier strings into connected components.
//
// It is deliberately keyed on identifier strings rather than record indices:
// records are joined *because* they share identifiers, and a record contributing
// several identifiers is what creates a bridge between two identifier spaces.
// Keying on records would lose exactly that.
type unionFind struct {
	parent map[string]string
	rank   map[string]int
}

func newUnionFind() *unionFind {
	return &unionFind{parent: map[string]string{}, rank: map[string]int{}}
}

func (u *unionFind) add(id string) {
	if _, seen := u.parent[id]; !seen {
		u.parent[id] = id
	}
}

// find returns the representative of id's component, with path compression.
func (u *unionFind) find(id string) string {
	u.add(id)
	root := id
	for u.parent[root] != root {
		root = u.parent[root]
	}
	for u.parent[id] != root {
		next := u.parent[id]
		u.parent[id] = root
		id = next
	}
	return root
}

// link merges the components containing a and b.
func (u *unionFind) link(a, b string) {
	ra, rb := u.find(a), u.find(b)
	if ra == rb {
		return
	}
	if u.rank[ra] < u.rank[rb] {
		ra, rb = rb, ra
	}
	u.parent[rb] = ra
	if u.rank[ra] == u.rank[rb] {
		u.rank[ra]++
	}
}
