package reader

import (
	bolt "go.etcd.io/bbolt"
)

// GetAdvisory returns the single advisory at source/pkg/cve, or
// (zero, false) if absent. No Red Hat Entries filtering — use
// FindAdvisories with Repositories/NVRs for that.
func (d *Database) GetAdvisory(source, pkgName, cveID string) (AdvisoryRow, bool, error) {
	var (
		row AdvisoryRow
		ok  bool
	)
	err := d.bdb.View(func(tx *bolt.Tx) error {
		row, ok = getOneAdvisory(tx, source, pkgName, cveID)
		return nil
	})
	return row, ok, err
}
