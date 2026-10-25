// Package skills embeds the portable operator skill shipped with Aegis.
package skills

import "embed"

// Files contains documentation only; no credentials or executable scripts.
//
//go:embed aegis-waf
var Files embed.FS
