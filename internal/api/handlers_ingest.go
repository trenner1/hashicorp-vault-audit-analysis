package api

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/go-chi/chi/v5"
)

// UploadResponse is returned after a successful file upload.
type UploadResponse struct {
	Filename string `json:"filename"`
	Path     string `json:"path"`
	Size     int64  `json:"size"`
}

// handleUpload accepts a multipart log file upload (field name "file").
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if err := os.MkdirAll(s.uploadDir, 0755); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create upload directory")
		return
	}

	// 2 GB max
	if err := r.ParseMultipartForm(2 << 30); err != nil {
		writeError(w, http.StatusBadRequest, "failed to parse multipart form")
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "no file provided (field name: file)")
		return
	}
	defer file.Close()

	// Timestamp prefix avoids collisions.
	ts := time.Now().Format("20060102150405")
	filename := fmt.Sprintf("%s_%s", ts, handler.Filename)
	destPath := filepath.Join(s.uploadDir, filename)

	dst, err := os.Create(destPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create destination file")
		return
	}
	defer dst.Close()

	written, err := io.Copy(dst, file)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write file")
		return
	}

	writeJSON(w, http.StatusOK, UploadResponse{
		Filename: filename,
		Path:     destPath,
		Size:     written,
	})
}

// UploadedFile describes a file in the upload directory.
type UploadedFile struct {
	Filename  string    `json:"filename"`
	Path      string    `json:"path"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

// handleListFiles returns all files currently in the upload directory.
// GET /api/v1/ingest/files
func (s *Server) handleListFiles(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(s.uploadDir)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, []UploadedFile{})
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to list upload directory")
		return
	}

	files := make([]UploadedFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		fullPath := filepath.Join(s.uploadDir, entry.Name())
		files = append(files, UploadedFile{
			Filename:  entry.Name(),
			Path:      fullPath,
			Size:      info.Size(),
			CreatedAt: info.ModTime(),
		})
	}

	// Sort newest first
	sort.Slice(files, func(i, j int) bool {
		return files[i].CreatedAt.After(files[j].CreatedAt)
	})

	writeJSON(w, http.StatusOK, files)
}

// handleDeleteFile removes a single uploaded file by filename.
// DELETE /api/v1/ingest/files/{filename}
func (s *Server) handleDeleteFile(w http.ResponseWriter, r *http.Request) {
	filename := chi.URLParam(r, "filename")
	// Reject any path traversal attempt.
	if filepath.Base(filename) != filename || filename == "." || filename == ".." {
		writeError(w, http.StatusBadRequest, "invalid filename")
		return
	}

	path := filepath.Join(s.uploadDir, filename)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "file not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete file")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "filename": filename})
}
