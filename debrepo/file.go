package debrepo

import "crypto"

// FileMeta is metadata associated with a file stored on a package repository.
type FileMeta struct {
	HashSum []byte
	Hash    crypto.Hash
	Size    int64
}
