package debrepo

import (
	"crypto"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"reflect"
	"sync"

	"golang.org/x/net/context"
	"golang.org/x/net/context/ctxhttp"
)

// FileMeta is metadata associated with a file stored on a package repository.
type FileMeta struct {
	HashSum []byte
	Hash    crypto.Hash
	Size    int64
}

// File is a file stored on a package repository.
type File struct {
	meta FileMeta
	url  string
	open bool
	mu   sync.Mutex
	rc   io.ReadCloser
	hash hash.Hash
}

// Open returns a Reader with the contents of the file. Open must be followed
// by a close to release resources. Reads update a running hash of the file
// contents which can be checked by calling CheckHash. CheckHash should be
// called after the entire contents of the file have been read to verify the
// file matches the expected hash sum.
func (f *File) Open(ctx context.Context, client *http.Client) (io.Reader, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// TODO: Make sure hash type is set to a compatible hash type
	if f.open {
		return nil, errors.New("file already open")
	}
	resp, err := ctxhttp.Get(ctx, client, f.url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("error requesting file: %v", err)
	}
	f.rc = resp.Body
	f.open = true
	f.hash = f.meta.Hash.New()
	r := io.TeeReader(resp.Body, f.hash)
	return r, nil
}

// Close closes the underlying web request.
func (f *File) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.open {
		return nil
	}
	f.open = false
	return f.rc.Close()
}

// CheckHash returns an error if the read contents does not match the expected
// hash sum.
func (f *File) CheckHash() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hash == nil {
		return errors.New("no hash data for file")
	}
	var hash []byte
	hash = f.hash.Sum(hash)
	if !reflect.DeepEqual(hash, f.meta.HashSum) {
		return errors.New("hash does not match")
	}
	return nil
}

// Size returns the file size.
func (f *File) Size() int64 {
	return f.meta.Size
}
