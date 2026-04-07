// Package reader provides a smart file opener with automatic decompression.
//
// Supported formats:
//   - Plain text files
//   - Gzip compressed files (.gz)
//   - Zstandard compressed files (.zst)
package reader

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
)

// OpenFile opens a file for reading, transparently decompressing it
// based on its extension:
//   - .gz  → gzip decompression
//   - .zst → zstandard decompression
//   - else → plain file
//
// The caller is responsible for closing the returned ReadCloser.
func OpenFile(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	switch filepath.Ext(path) {
	case ".gz":
		gr, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("gzip reader for %s: %w", path, err)
		}
		// Wrap so both the gzip reader and the underlying file get closed.
		return &multiCloser{Reader: gr, closers: []io.Closer{gr, f}}, nil

	case ".zst":
		dec, err := zstd.NewReader(f)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("zstd reader for %s: %w", path, err)
		}
		return &zstdCloser{dec: dec, f: f}, nil

	default:
		return f, nil
	}
}

// multiCloser wraps a Reader and closes multiple io.Closers on Close().
type multiCloser struct {
	io.Reader
	closers []io.Closer
}

func (mc *multiCloser) Close() error {
	var first error
	for _, c := range mc.closers {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// zstdCloser wraps a zstd.Decoder (which uses Close not io.Closer interface).
type zstdCloser struct {
	dec *zstd.Decoder
	f   *os.File
}

func (zc *zstdCloser) Read(p []byte) (int, error) { return zc.dec.Read(p) }
func (zc *zstdCloser) Close() error {
	zc.dec.Close()
	return zc.f.Close()
}
