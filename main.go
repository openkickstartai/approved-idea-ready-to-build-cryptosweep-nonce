package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var scanExts = map[string]bool{
	".go": true, ".py": true, ".java": true, ".js": true,
	".ts": true, ".rb": true, ".rs": true, ".c": true,
	".cpp": true, ".cs": true, ".kt": true, ".swift": true,
}

var skipDirs = map[string]bool{
	".git": true, "vendor": true, "node_modules": true,
	"__pycache__": true, "target": true, ".idea": true,
}

func main() {
	target := "."
	if len(os.Args) > 1 {
		target = os.Args[1]
	}
	var all []Finding
	filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !scanExts[filepath.Ext(path)] {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		all = append(all, Scan(path, string(data))...)
		return nil
	})
	if len(all) == 0 {
		fmt.Println("✅ No crypto misuse found.")
		os.Exit(0)
	}
	fmt.Printf("🔍 CryptoSweep: %d issue(s)\n\n", len(all))
	for _, f := range all {
		fmt.Printf("[%s] %s (CWE: %s)\n", f.Rule.Severity, f.Rule.Name, f.Rule.CWE)
		fmt.Printf("  → %s:%d\n", f.File, f.Line)
		fmt.Printf("  │ %s\n\n", strings.TrimSpace(f.Match))
	}
	os.Exit(1)
}
