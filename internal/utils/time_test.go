package utils

import (
	"testing"
	"time"
)

func TestParseTimestamp(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
		wantUTC string
	}{
		{
			name:    "RFC3339Nano",
			input:   "2025-01-15T10:30:00.123456789Z",
			wantUTC: "2025-01-15 10:30:00 +0000 UTC",
		},
		{
			name:    "RFC3339 no nanos",
			input:   "2025-01-15T10:30:00Z",
			wantUTC: "2025-01-15 10:30:00 +0000 UTC",
		},
		{
			name:    "RFC3339 with offset",
			input:   "2025-01-15T10:30:00+05:00",
			wantUTC: "2025-01-15 05:30:00 +0000 UTC",
		},
		{
			name:    "invalid",
			input:   "not-a-timestamp",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTimestamp(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ParseTimestamp(%q): expected error, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTimestamp(%q): unexpected error: %v", tc.input, err)
			}
			gotUTC := got.UTC().String()
			if gotUTC != tc.wantUTC {
				t.Errorf("ParseTimestamp(%q) = %q, want %q", tc.input, gotUTC, tc.wantUTC)
			}
		})
	}
}

func TestFormatTimestamp(t *testing.T) {
	ts := time.Date(2025, 6, 15, 9, 5, 3, 0, time.UTC)
	got := FormatTimestamp(ts)
	want := "2025-06-15 09:05:03 UTC"
	if got != want {
		t.Errorf("FormatTimestamp = %q, want %q", got, want)
	}

	// Non-UTC timezone gets converted.
	loc := time.FixedZone("EST", -5*3600)
	ts2 := time.Date(2025, 6, 15, 9, 0, 0, 0, loc)
	got2 := FormatTimestamp(ts2)
	want2 := "2025-06-15 14:00:00 UTC"
	if got2 != want2 {
		t.Errorf("FormatTimestamp (non-UTC) = %q, want %q", got2, want2)
	}
}

func TestDurationHuman(t *testing.T) {
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		seconds int
		want    string
	}{
		{0, "0 seconds"},
		{59, "59 seconds"},
		{60, "1 minutes"},
		{90, "1 minutes"},
		{3599, "59 minutes"},
		{3600, "1.0 hours"},
		{5400, "1.5 hours"},
		{86399, "24.0 hours"},
		{86400, "1.0 days"},
		{172800, "2.0 days"},
	}

	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			end := base.Add(time.Duration(tc.seconds) * time.Second)
			got := DurationHuman(base, end)
			if got != tc.want {
				t.Errorf("DurationHuman(%ds) = %q, want %q", tc.seconds, got, tc.want)
			}
		})
	}
}

func TestHoursBetween(t *testing.T) {
	cases := []struct {
		name    string
		first   string
		last    string
		want    float64
		wantErr bool
	}{
		{
			name:  "1 hour",
			first: "2025-01-01T00:00:00Z",
			last:  "2025-01-01T01:00:00Z",
			want:  1.0,
		},
		{
			name:  "24 hours",
			first: "2025-01-01T00:00:00Z",
			last:  "2025-01-02T00:00:00Z",
			want:  24.0,
		},
		{
			name:  "0 hours",
			first: "2025-01-01T12:00:00Z",
			last:  "2025-01-01T12:00:00Z",
			want:  0.0,
		},
		{
			name:    "bad first",
			first:   "not-a-time",
			last:    "2025-01-01T01:00:00Z",
			wantErr: true,
		},
		{
			name:    "bad last",
			first:   "2025-01-01T00:00:00Z",
			last:    "not-a-time",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := HoursBetween(tc.first, tc.last)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("HoursBetween = %v, want %v", got, tc.want)
			}
		})
	}
}
