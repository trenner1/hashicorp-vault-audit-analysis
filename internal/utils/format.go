// Package utils provides shared utility functions used across commands.
package utils

import "strconv"

// FormatNumber formats an integer with comma separators for thousands.
//
//	FormatNumber(1234567) → "1,234,567"
func FormatNumber(n int) string {
	s := strconv.Itoa(n)
	if n < 0 {
		// strip minus, format, re-add
		s = s[1:]
	}
	out := make([]byte, 0, len(s)+(len(s)-1)/3)
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c))
	}
	if n < 0 {
		return "-" + string(out)
	}
	return string(out)
}
