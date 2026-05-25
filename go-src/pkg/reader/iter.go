package reader

import (
	"encoding/json"
	"fmt"
	"sync"

	bolt "go.etcd.io/bbolt"
)

// AdvisoryRow is one (source, package, cve) advisory leaf. `Raw` is
// the verbatim bbolt value, passed through so the Python layer can
// extract known fields and stash the rest in Advisory.extra.
type AdvisoryRow struct {
	Source      string          `json:"source"`
	PackageName string          `json:"package_name"`
	CveID       string          `json:"cve_id"`
	Raw         json.RawMessage `json:"raw"`
}

// MetaRow is one entry in the aggregated `vulnerability` bucket.
type MetaRow struct {
	CveID string          `json:"cve_id"`
	Raw   json.RawMessage `json:"raw"`
}

// AdvisoryIterator streams every (source, package, cve) advisory row.
// Single-consumer by Python convention; Next + Close mutually exclude
// via a mutex.
type AdvisoryIterator struct {
	tx *bolt.Tx
	mu sync.Mutex

	sources          []string // top-level non-reserved buckets, snapshot
	srcIdx           int
	srcBucket        *bolt.Bucket
	pkgCursor        *bolt.Cursor
	currentPkg       []byte
	currentPkgBkt    *bolt.Bucket
	cveCursor        *bolt.Cursor
	cveCursorStarted bool // false → use First(); true → use Next()

	closed bool
}

func (d *Database) OpenAdvisoryIterator() (*AdvisoryIterator, error) {
	tx, err := d.bdb.Begin(false)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	it := &AdvisoryIterator{tx: tx}
	if err := tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
		s := string(name)
		if _, reserved := reservedTopLevelBuckets[s]; reserved {
			return nil
		}
		it.sources = append(it.sources, s)
		return nil
	}); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return it, nil
}

// MaxBatchSize caps any single IterNext call. A hostile or buggy
// caller passing batchSize=10**9 would otherwise force `make` to
// pre-allocate billions of slots and OOM the process.
const MaxBatchSize = 100_000

// MaxRawValueBytes caps the size of any single bbolt value we copy
// into a row. Defends against crafted DBs containing pathologically
// large values. Real trivy-db values are <100 KiB; 16 MiB is generous.
const MaxRawValueBytes = 16 << 20

// copyRaw returns a defensive copy of v bounded by MaxRawValueBytes.
// (nil, false) means the value is oversized; the caller should skip
// this row rather than propagate untrusted bytes through the rest of
// the pipeline.
func copyRaw(v []byte) (json.RawMessage, bool) {
	if len(v) > MaxRawValueBytes {
		return nil, false
	}
	return append(json.RawMessage{}, v...), true
}

// Next returns up to batchSize rows. (nil, nil) at EOF.
func (it *AdvisoryIterator) Next(batchSize int) ([]AdvisoryRow, error) {
	if batchSize <= 0 {
		batchSize = 1000
	}
	if batchSize > MaxBatchSize {
		batchSize = MaxBatchSize
	}
	it.mu.Lock()
	defer it.mu.Unlock()
	if it.closed {
		return nil, nil
	}
	out := make([]AdvisoryRow, 0, batchSize)
	for len(out) < batchSize {
		row, ok := it.advance()
		if !ok {
			break
		}
		out = append(out, row)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// advance moves cursors to the next leaf. Returns (row, true) or
// (zero, false) at EOF. Caller holds it.mu.
func (it *AdvisoryIterator) advance() (AdvisoryRow, bool) {
	for {
		// Position into a source bucket if we're not in one.
		if it.srcBucket == nil {
			if it.srcIdx >= len(it.sources) {
				return AdvisoryRow{}, false
			}
			it.srcBucket = it.tx.Bucket([]byte(it.sources[it.srcIdx]))
			it.srcIdx++
			if it.srcBucket == nil {
				continue
			}
			it.pkgCursor = it.srcBucket.Cursor()
			it.currentPkg, _ = it.pkgCursor.First()
			it.currentPkgBkt = nil
			it.cveCursor = nil
		}

		// EOF of this source's packages — advance to next source.
		if it.currentPkg == nil {
			it.srcBucket = nil
			continue
		}

		// Enter the current package's sub-bucket if not already in it.
		if it.currentPkgBkt == nil {
			it.currentPkgBkt = it.srcBucket.Bucket(it.currentPkg)
			if it.currentPkgBkt == nil {
				// Leaf at source/pkg (unusual). Skip.
				it.currentPkg, _ = it.pkgCursor.Next()
				continue
			}
			it.cveCursor = it.currentPkgBkt.Cursor()
			it.cveCursorStarted = false
		}

		var k, v []byte
		if it.cveCursorStarted {
			k, v = it.cveCursor.Next()
		} else {
			k, v = it.cveCursor.First()
			it.cveCursorStarted = true
		}
		if k == nil {
			// End of CVEs in this package — advance to next package.
			it.currentPkg, _ = it.pkgCursor.Next()
			it.currentPkgBkt = nil
			it.cveCursor = nil
			it.cveCursorStarted = false
			continue
		}

		raw, okSize := copyRaw(v)
		if !okSize {
			// Oversized blob — skip this row.
			continue
		}
		return AdvisoryRow{
			Source:      it.sources[it.srcIdx-1],
			PackageName: string(it.currentPkg),
			CveID:       string(k),
			Raw:         raw,
		}, true
	}
}

func (it *AdvisoryIterator) Close() error {
	it.mu.Lock()
	defer it.mu.Unlock()
	if it.closed {
		return nil
	}
	it.closed = true
	if it.tx != nil {
		_ = it.tx.Rollback()
		it.tx = nil
	}
	return nil
}

// --- Meta iterator (vulnerability bucket only) ---

type MetaIterator struct {
	tx      *bolt.Tx
	mu      sync.Mutex
	cursor  *bolt.Cursor
	started bool
	closed  bool
}

func (d *Database) OpenMetaIterator() (*MetaIterator, error) {
	tx, err := d.bdb.Begin(false)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	it := &MetaIterator{tx: tx}
	bkt := tx.Bucket([]byte("vulnerability"))
	if bkt != nil {
		it.cursor = bkt.Cursor()
	}
	return it, nil
}

func (it *MetaIterator) Next(batchSize int) ([]MetaRow, error) {
	if batchSize <= 0 {
		batchSize = 1000
	}
	if batchSize > MaxBatchSize {
		batchSize = MaxBatchSize
	}
	it.mu.Lock()
	defer it.mu.Unlock()
	if it.closed || it.cursor == nil {
		return nil, nil
	}
	out := make([]MetaRow, 0, batchSize)
	for len(out) < batchSize {
		var k, v []byte
		if !it.started {
			k, v = it.cursor.First()
			it.started = true
		} else {
			k, v = it.cursor.Next()
		}
		if k == nil {
			break
		}
		raw, okSize := copyRaw(v)
		if !okSize {
			continue
		}
		out = append(out, MetaRow{
			CveID: string(k),
			Raw:   raw,
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func (it *MetaIterator) Close() error {
	it.mu.Lock()
	defer it.mu.Unlock()
	if it.closed {
		return nil
	}
	it.closed = true
	if it.tx != nil {
		_ = it.tx.Rollback()
		it.tx = nil
	}
	return nil
}
