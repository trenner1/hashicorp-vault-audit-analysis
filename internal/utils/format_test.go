package utils

import "testing"

func TestFormatNumber(t *testing.T) {
	cases := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{999, "999"},
		{1000, "1,000"},
		{9999, "9,999"},
		{10000, "10,000"},
		{100000, "100,000"},
		{1000000, "1,000,000"},
		{1234567, "1,234,567"},
		{-1, "-1"},
		{-1000, "-1,000"},
		{-1234567, "-1,234,567"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			got := FormatNumber(tc.input)
			if got != tc.want {
				t.Errorf("FormatNumber(%d) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
