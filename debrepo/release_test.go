package debrepo

import (
	"testing"

	"golang.org/x/net/context"
)

func TestGetRelease_InReleaseFilePresent(t *testing.T) {
	tr := NewTestRepository()
	defer tr.Close()
	defer func() {
		testhookGetReleaseFromInRelease = nop
	}()
	var returnedAfterInRelease bool
	testhookGetReleaseFromInRelease = func() {
		returnedAfterInRelease = true
	}

	release, err := GetRelease(context.Background(), nil, tr.Repository())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(release.Bytes) == 0 || len(release.Plaintext) == 0 || release.ArmoredSignature == nil {
		t.Fatal("expected release not empty")
	}
	if !returnedAfterInRelease {
		t.Fatal("expected to have only downloaded InRelease file if its present on server")
	}
}

func TestGetRelease_InReleaseFileNotPresent(t *testing.T) {
	tr := NewTestRepository()
	defer tr.Close()
	defer func() {
		testhookGetReleaseFromRelease = nop
	}()
	var downloadedReleaseFile bool
	testhookGetReleaseFromRelease = func() {
		downloadedReleaseFile = true
	}
	tr.BlockFile("InRelease")

	release, err := GetRelease(context.Background(), nil, tr.Repository())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(release.Plaintext) == 0 || release.ArmoredSignature == nil {
		t.Fatal("expected release not empty")
	}
	if !downloadedReleaseFile {
		t.Fatal("expected to have downloaded Release and Release.gpg when InRelease not on server")
	}
}

func TestRelease_CheckSignature_FromInRelease(t *testing.T) {
	tr := NewTestRepository()
	defer tr.Close()
	release, _ := GetRelease(context.Background(), nil, tr.Repository())
	signer, err := release.CheckSignature(tr.KeyRing())
	if err != nil {
		t.Fatalf("InRelease: unexpected error verifying signature: %v", err)
	}
	if signer == nil {
		t.Fatal("InRelease: expected signer not empty")
	}
}

func TestRelease_CheckSignature_FromRelease(t *testing.T) {
	tr := NewTestRepository()
	defer tr.Close()
	tr.BlockFile("InRelease")
	release, _ := GetRelease(context.Background(), nil, tr.Repository())
	signer, err := release.CheckSignature(tr.KeyRing())
	if err != nil {
		t.Fatalf("Release: unexpected error verifying signature: %v", err)
	}
	if signer == nil {
		t.Fatal("Release: expected signer not empty")
	}
}
