package app

import (
	"bytes"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"
)

// signatureFS exposes an immutable PostgreSQL bundle through fs.FS. It never
// resolves host paths or follows links, including Coraza's @ aliases.
type signatureFS map[string][]byte

func (files signatureFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if data, ok := files[name]; ok {
		return &signatureFile{reader: bytes.NewReader(data), info: signatureInfo{name: path.Base(name), size: int64(len(data))}}, nil
	}
	entries, e := files.ReadDir(name)
	if e != nil {
		return nil, e
	}
	return &signatureFile{info: signatureInfo{name: path.Base(name), directory: true}, entries: entries}, nil
}
func (files signatureFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	children := map[string]signatureInfo{}
	prefix := ""
	if name != "." {
		prefix = name + "/"
	}
	for filename, data := range files {
		remaining, ok := strings.CutPrefix(filename, prefix)
		if !ok {
			continue
		}
		child, _, directory := strings.Cut(remaining, "/")
		if child == "" {
			continue
		}
		info := signatureInfo{name: child, directory: directory}
		if !directory {
			info.size = int64(len(data))
		}
		children[child] = info
	}
	if len(children) == 0 && name != "." {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	names := make([]string, 0, len(children))
	for child := range children {
		names = append(names, child)
	}
	sort.Strings(names)
	entries := make([]fs.DirEntry, 0, len(names))
	for _, child := range names {
		entries = append(entries, children[child])
	}
	return entries, nil
}

type signatureInfo struct {
	name      string
	size      int64
	directory bool
}

func (i signatureInfo) Name() string { return i.name }
func (i signatureInfo) Size() int64  { return i.size }
func (i signatureInfo) IsDir() bool  { return i.directory }
func (i signatureInfo) Mode() fs.FileMode {
	if i.directory {
		return fs.ModeDir | 0555
	}
	return 0444
}
func (i signatureInfo) Type() fs.FileMode          { return i.Mode().Type() }
func (i signatureInfo) Info() (fs.FileInfo, error) { return i, nil }
func (i signatureInfo) ModTime() time.Time         { return time.Time{} }
func (i signatureInfo) Sys() any                   { return nil }

type signatureFile struct {
	reader   *bytes.Reader
	info     signatureInfo
	entries  []fs.DirEntry
	position int
}

func (f *signatureFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *signatureFile) Close() error               { return nil }
func (f *signatureFile) Read(buffer []byte) (int, error) {
	if f.reader == nil {
		return 0, fs.ErrInvalid
	}
	return f.reader.Read(buffer)
}
func (f *signatureFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if !f.info.directory {
		return nil, fs.ErrInvalid
	}
	if n > 0 && f.position >= len(f.entries) {
		return nil, io.EOF
	}
	end := len(f.entries)
	if n > 0 {
		end = min(end, f.position+n)
	}
	entries := f.entries[f.position:end]
	f.position = end
	return entries, nil
}
