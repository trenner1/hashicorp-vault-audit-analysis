package utils

import (
	"fmt"
	"time"
)

// ParseTimestamp parses an RFC 3339 / ISO 8601 timestamp string as used
// in Vault audit logs (e.g. "2025-10-07T12:00:00.000Z").
func ParseTimestamp(ts string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		// Fallback: try without nanoseconds
		t, err = time.Parse(time.RFC3339, ts)
	}
	return t, err
}

// FormatTimestamp formats a time.Time for human-readable display.
func FormatTimestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

// DurationHuman returns a human-readable string for the duration between
// two timestamps (e.g. "3.5 hours", "2.1 days").
func DurationHuman(start, end time.Time) string {
	d := end.Sub(start)
	seconds := int64(d.Seconds())

	switch {
	case seconds < 60:
		return fmt.Sprintf("%d seconds", seconds)
	case seconds < 3600:
		return fmt.Sprintf("%d minutes", seconds/60)
	case seconds < 86400:
		return fmt.Sprintf("%.1f hours", float64(seconds)/3600)
	default:
		return fmt.Sprintf("%.1f days", float64(seconds)/86400)
	}
}

// HoursBetween returns the number of hours between two RFC 3339 timestamp strings.
// Returns 0 and a non-nil error if either string cannot be parsed.
func HoursBetween(first, last string) (float64, error) {
	t1, err := ParseTimestamp(first)
	if err != nil {
		return 0, fmt.Errorf("parse first timestamp %q: %w", first, err)
	}
	t2, err := ParseTimestamp(last)
	if err != nil {
		return 0, fmt.Errorf("parse last timestamp %q: %w", last, err)
	}
	return t2.Sub(t1).Hours(), nil
}
