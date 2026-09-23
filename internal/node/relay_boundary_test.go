package node

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// This architecture test prevents plaintext/crypto work from drifting back
// into the exterior WebSocket relay during future refactors.
func TestRelayFilesDoNotHandleSensitiveContent(t *testing.T) {
	for _, name := range []string{"handler.go", "scorer.go"} {
		path := filepath.Join(".", name)
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			importPath := strings.Trim(spec.Path.Value, `"`)
			if strings.Contains(importPath, "/crypto") || strings.Contains(importPath, "/security") {
				t.Fatalf("%s imports sensitive implementation package %s", name, importPath)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if ok && (strings.Contains(identifier.Name, "Decrypt") || identifier.Name == "ResponseText") {
				t.Errorf("%s contains sensitive identifier %s", name, identifier.Name)
			}
			return true
		})
	}
}
