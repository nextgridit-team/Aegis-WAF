// Package community embeds the reviewed initial mitigation catalogue.
package community

import "embed"

// Files contains the shipped manifest and individual rules, not executable code.
//
//go:embed *.json
var Files embed.FS
