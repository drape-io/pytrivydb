package reader

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// MaxJSONDepth bounds the maximum nesting depth we'll accept when
// decoding attacker-controlled bbolt content. Real trivy-db values
// nest at most 3-4 levels deep (Advisory → Entries[] → fields); 32
// is generous defense-in-depth against crafted DBs that try to
// blow the goroutine stack via deeply-nested arrays.
const MaxJSONDepth = 32

// safeUnmarshal pre-scans `data` for nesting depth above MaxJSONDepth,
// then delegates to json.Unmarshal. Used at every site that decodes
// bbolt blob content; complements the per-value byte cap from
// MaxRawValueBytes (a small byte stream can still nest deeply via
// many empty array openers).
func safeUnmarshal(data []byte, v any) error {
	if err := scanJSONDepth(data, MaxJSONDepth); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func scanJSONDepth(data []byte, maxDepth int) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			// EOF or malformed JSON — return nil either way. Real parse
			// errors are surfaced by the caller's json.Unmarshal with a
			// more informative message.
			return nil
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '[', '{':
				depth++
				if depth > maxDepth {
					return fmt.Errorf("%w: JSON nesting depth exceeds %d", ErrCorrupt, maxDepth)
				}
			case ']', '}':
				depth--
			}
		}
	}
}
