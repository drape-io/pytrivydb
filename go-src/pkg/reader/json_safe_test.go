package reader

import (
	"errors"
	"strings"
	"testing"
)

func TestSafeUnmarshalAcceptsShallowJSON(t *testing.T) {
	var v any
	if err := safeUnmarshal([]byte(`{"Entries":[{"Affected":[1,2,3]}]}`), &v); err != nil {
		t.Fatalf("expected success on shallow JSON, got %v", err)
	}
}

func TestSafeUnmarshalRejectsDeepNesting(t *testing.T) {
	// Build a deeply-nested array of empty arrays exceeding MaxJSONDepth.
	deep := strings.Repeat("[", MaxJSONDepth+5) + strings.Repeat("]", MaxJSONDepth+5)
	var v any
	err := safeUnmarshal([]byte(deep), &v)
	if err == nil {
		t.Fatal("expected depth-exceeded error, got nil")
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Errorf("expected ErrCorrupt-wrapped error, got %v", err)
	}
}

func TestSafeUnmarshalLetsRegularParseErrorsThrough(t *testing.T) {
	var v any
	err := safeUnmarshal([]byte(`{not valid json`), &v)
	if err == nil {
		t.Fatal("expected json parse error, got nil")
	}
	// Should not be ErrCorrupt-wrapped (depth-scan tolerates the error
	// so the real Unmarshal can produce a more informative message).
	if errors.Is(err, ErrCorrupt) {
		t.Errorf("expected raw json error, got ErrCorrupt-wrapped: %v", err)
	}
}
