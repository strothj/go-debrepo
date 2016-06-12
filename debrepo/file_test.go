package debrepo

import (
	"crypto"
	"io"
	"io/ioutil"
	"testing"

	"golang.org/x/net/context"
)

var (
	matchingHash = FileMeta{
		HashSum: decodeHexString("7b7877be9dd6ac0e6b8baffbc36ce09c"),
		Hash:    crypto.MD5,
		Size:    1557985,
	}
	nonMatchingHash = FileMeta{
		HashSum: decodeHexString("000000be9dd6ac0e6b8baffbc36ce09c"),
		Hash:    crypto.MD5,
		Size:    1557985,
	}
)

func TestFileOpen_FileMatchesHash_NoError(t *testing.T) {
	tr := NewTestRepository()
	defer tr.Close()
	file := newTestFile(tr, matchingHash)
	r, err := file.Open(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer file.Close()
	io.Copy(ioutil.Discard, r)
	if err := file.CheckHash(); err != nil {
		t.Fatalf("unexpected hash failure: %v", err)
	}
}

func TestFileOpen_FileDoesNotMatchHash_Error(t *testing.T) {
	tr := NewTestRepository()
	defer tr.Close()
	file := newTestFile(tr, nonMatchingHash)
	r, err := file.Open(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer file.Close()
	io.Copy(ioutil.Discard, r)
	if err := file.CheckHash(); err == nil {
		t.Fatal("expected err with mismatched hash values")
	}
}

func newTestFile(tr *testRepository, meta FileMeta) *File {
	return &File{
		meta: meta,
		url:  tr.URL + "/ubuntu/dists/xenial/main/binary-amd64/Packages.gz",
	}
}
