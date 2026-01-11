package database

import (
	"os"
	"path/filepath"
	"runtime"
)

// FindMigrationsPath tries to find the migrations directory
// by looking in common locations relative to the current working directory
func FindMigrationsPath() (string, error) {
	possiblePaths := []string{
		"migrations",
		"./migrations", 
		"../migrations",
		"../../migrations",
	}

	// Get the directory of the current executable
	if _, filename, _, ok := runtime.Caller(0); ok {
		projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(filename))) // pkg/database -> pkg -> root
		possiblePaths = append(possiblePaths, filepath.Join(projectRoot, "migrations"))
	}

	// Get current working directory
	if wd, err := os.Getwd(); err == nil {
		possiblePaths = append(possiblePaths, filepath.Join(wd, "migrations"))
	}

	// Try each possible path
	for _, path := range possiblePaths {
		if absPath, err := filepath.Abs(path); err == nil {
			if stat, err := os.Stat(absPath); err == nil && stat.IsDir() {
				return absPath, nil
			}
		}
	}

	return "", os.ErrNotExist
}