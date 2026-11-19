// Package docs holds documents that the siegekit binary prints.
package docs

import _ "embed"

// Agents is the guide for AI coding assistants (agents.md).
//
//go:embed agents.md
var Agents string
