// Package reader is the bbolt-direct read layer that powers
// pytrivydb. It opens trivy-db databases without trivy-db's
// pkg/db global singleton, supports N concurrent DBs per process,
// and validates schema version via the sibling metadata.json file
// (NOT a bbolt bucket — see plan §3 + pkg/metadata/metadata.go:12).
package reader

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

// SupportedSchemaVersion is the trivy-db on-disk schema this reader
// understands. Aligned with go-src/pkg/writer.SupportedSchemaVersion.
const SupportedSchemaVersion = 2

// Reserved top-level buckets skipped during full-DB iteration.
// Order doesn't matter — used as a set in iter.go.
var reservedTopLevelBuckets = map[string]struct{}{
	"vulnerability":        {},
	"vulnerability-detail": {},
	"vulnerability-id":     {},
	"Red Hat CPE":          {},
	"data-source":          {},
	"trivy-db-metadata":    {},
}

// Sentinel error types. The CGO layer translates these to specific
// Python exceptions in cmd/pytrivydb/main.go.
var (
	ErrNotFound          = errors.New("trivy.db not found")
	ErrMetadataNotFound  = errors.New("metadata.json not found")
	ErrCorrupt           = errors.New("database is corrupt")
	ErrUnsupportedSchema = errors.New("unsupported schema version")
)

// Metadata mirrors trivy-db's pkg/metadata.Metadata.
type Metadata struct {
	Version      int       `json:",omitempty"`
	NextUpdate   time.Time `json:",omitempty"`
	UpdatedAt    time.Time `json:",omitempty"`
	DownloadedAt time.Time `json:",omitempty"`
}

// Database is an opened trivy-db handle. Each Database owns its own
// *bolt.DB — no package globals. Safe for concurrent reads; callers
// must call Close exactly once.
type Database struct {
	bdb *bolt.DB
}

// Open validates {dbDir}/metadata.json and opens {dbDir}/trivy.db
// read-only. Returns ErrNotFound, ErrMetadataNotFound,
// ErrUnsupportedSchema, or ErrCorrupt sentinels wrapped via fmt.Errorf
// for the CGO layer to translate into typed Python exceptions.
func Open(dbDir string) (*Database, error) {
	dbPath := filepath.Join(dbDir, "trivy.db")
	metaPath := filepath.Join(dbDir, "metadata.json")

	mdBytes, err := os.ReadFile(metaPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrMetadataNotFound, metaPath)
		}
		return nil, fmt.Errorf("%w: read metadata.json: %v", ErrCorrupt, err)
	}
	var md Metadata
	if err := json.Unmarshal(mdBytes, &md); err != nil {
		return nil, fmt.Errorf("%w: parse metadata.json: %v", ErrCorrupt, err)
	}
	if md.Version != SupportedSchemaVersion {
		return nil, fmt.Errorf("%w: got %d, this build of pytrivydb supports version %d",
			ErrUnsupportedSchema, md.Version, SupportedSchemaVersion)
	}

	if _, err := os.Stat(dbPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, dbPath)
		}
		return nil, fmt.Errorf("%w: stat trivy.db: %v", ErrCorrupt, err)
	}

	bdb, err := bolt.Open(dbPath, 0o600, &bolt.Options{
		ReadOnly: true,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: bbolt open: %v", ErrCorrupt, err)
	}

	return &Database{bdb: bdb}, nil
}

// Close releases the bbolt mmap + file descriptor. Idempotent.
func (d *Database) Close() error {
	if d == nil || d.bdb == nil {
		return nil
	}
	err := d.bdb.Close()
	d.bdb = nil
	return err
}

// ListSources enumerates top-level buckets in the bbolt file,
// filtering out reserved/internal buckets.
func (d *Database) ListSources() ([]string, error) {
	var sources []string
	err := d.bdb.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			s := string(name)
			if _, reserved := reservedTopLevelBuckets[s]; reserved {
				return nil
			}
			sources = append(sources, s)
			return nil
		})
	})
	return sources, err
}
