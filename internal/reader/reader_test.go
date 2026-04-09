package reader

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

const sampleContent = "line one\nline two\nline three\n"

// writeTempFile writes data to a temp file with the given extension and
// returns the path. The file is removed by t.Cleanup.
func writeTempFile(t *testing.T, ext string, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "reader-test-*"+ext)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	return f.Name()
}

func gzipBytes(data []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(data) //nolint:errcheck
	w.Close()
	return buf.Bytes()
}

func zstdBytes(data []byte) []byte {
	var buf bytes.Buffer
	w, _ := zstd.NewWriter(&buf)
	w.Write(data) //nolint:errcheck
	w.Close()
	return buf.Bytes()
}

func readAll(t *testing.T, rc io.ReadCloser) string {
	t.Helper()
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(b)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestOpenFilePlain(t *testing.T) {
	path := writeTempFile(t, ".log", []byte(sampleContent))
	rc, err := OpenFile(path)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	got := readAll(t, rc)
	if got != sampleContent {
		t.Errorf("plain read = %q, want %q", got, sampleContent)
	}
}

func TestOpenFileGzip(t *testing.T) {
	path := writeTempFile(t, ".gz", gzipBytes([]byte(sampleContent)))
	rc, err := OpenFile(path)
	if err != nil {
		t.Fatalf("OpenFile(.gz): %v", err)
	}
	got := readAll(t, rc)
	if got != sampleContent {
		t.Errorf("gzip read = %q, want %q", got, sampleContent)
	}
}

func TestOpenFileZstd(t *testing.T) {
	path := writeTempFile(t, ".zst", zstdBytes([]byte(sampleContent)))
	rc, err := OpenFile(path)
	if err != nil {
		t.Fatalf("OpenFile(.zst): %v", err)
	}
	got := readAll(t, rc)
	if got != sampleContent {
		t.Errorf("zstd read = %q, want %q", got, sampleContent)
	}
}

func TestOpenFileNotFound(t *testing.T) {
	_, err := OpenFile(filepath.Join(t.TempDir(), "does-not-exist.log"))
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestOpenFileInvalidGzip(t *testing.T) {
	// Write garbage bytes with .gz extension.
	path := writeTempFile(t, ".gz", []byte("not gzip content"))
	_, err := OpenFile(path)
	if err == nil {
		t.Error("expected error for invalid gzip, got nil")
	}
}

func TestOpenFileClose(t *testing.T) {
	// Ensure Close() can be called without panicking for each format.
	formats := []struct {
		ext  string
		data []byte
	}{
		{".log", []byte(sampleContent)},
		{".gz", gzipBytes([]byte(sampleContent))},
		{".zst", zstdBytes([]byte(sampleContent))},
	}
	for _, f := range formats {
		t.Run(f.ext, func(t *testing.T) {
			path := writeTempFile(t, f.ext, f.data)
			rc, err := OpenFile(path)
			if err != nil {
				t.Fatalf("OpenFile: %v", err)
			}
			if err := rc.Close(); err != nil {
				t.Errorf("Close() = %v, want nil", err)
			}
		})
	}
}
