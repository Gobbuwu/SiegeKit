package checks

// PROTO (round 2): SiegeKit's .gitignore matcher for N1.
func ProtoIgnored(root, rel string) bool {
	ig := &ignores{root: root, cache: map[string][]ignoreRule{}}
	return ig.ignored(rel)
}
