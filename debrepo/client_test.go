package debrepo

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/pkg/errors"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/net/context"
)

func TestClientGetReleaseIndex_InReleasePresent_ReturnsRelease(t *testing.T) {
	inRelease, release, _, keyRing := newTestKeyRingAndRelease()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if expected, actual := "/ubuntu/dists/xenial/InRelease", r.URL.Path; expected != actual {
			t.Errorf("request url: expected=%v actual=%v", expected, actual)
		}
		if _, err := w.Write(inRelease); err != nil {
			t.Errorf("unexpected error writing InRelease to response: %v", err)
		}
	}))
	defer server.Close()

	repo, _ := ParseRepository("deb " + server.URL + "/ubuntu/" + " xenial main")
	client := &Client{KeyRing: keyRing, Architecture: "amd64"}
	actual, err := client.GetReleaseIndex(context.Background(), repo)
	if err != nil {
		t.Fatalf("unexpected error getting release: %v", err)
	}
	if expected, actual := release, actual; !reflect.DeepEqual(expected, actual) {
		t.Fatalf("expected=%v actual=%v", expected, actual)
	}
}

func TestClientGetReleaseIndex_ReleaseAndReleaseGPGPresent_ReturnsRelease(t *testing.T) {
	_, release, releaseGPG, keyRing := newTestKeyRingAndRelease()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ubuntu/dists/xenial/InRelease" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Path == "/ubuntu/dists/xenial/Release" {
			if _, err := w.Write(release); err != nil {
				t.Errorf("unexpected error writing Release to response: %v", err)
			}
			return
		}
		if r.URL.Path == "/ubuntu/dists/xenial/Release.gpg" {
			if _, err := w.Write(releaseGPG); err != nil {
				t.Errorf("unexpected error writing Release.gpg to response: %v", err)
			}
			return
		}
		t.Errorf("unexpected url: %v", r.URL)
	}))

	repo, _ := ParseRepository("deb " + server.URL + "/ubuntu/" + " xenial main")
	client := &Client{KeyRing: keyRing, Architecture: "amd64"}
	actual, err := client.GetReleaseIndex(context.Background(), repo)
	if err != nil {
		t.Fatalf("unexpected error getting release: %v", err)
	}
	if expected, actual := release, actual; !reflect.DeepEqual(expected, actual) {
		t.Fatalf("expected=%v actual=%v", expected, actual)
	}
}

func TestClientValidate_ValidClient_NoError(t *testing.T) {
	client := newTestValidClient()
	if err := client.validate(); err != nil {
		t.Fatalf("unexpected error validating valid client: %v", err)
	}
}

func TestClientValidate_NilKeyRing_ReturnsError(t *testing.T) {
	client := newTestValidClient()
	client.KeyRing = nil
	if err := client.validate(); err == nil {
		t.Fatal("expected error on nil keyring")
	}
}

func TestClientValidate_InvalidArchitecture_ReturnsError(t *testing.T) {
	client := newTestValidClient()
	client.Architecture = "invalid"
	if err := client.validate(); err == nil {
		t.Fatal("expected error on invalid architecture")
	}
}

func TestClientGetFile_FileExists_ReturnsByteSlice(t *testing.T) {
	filepath := "/exists.txt"
	expected := "expected"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if expected, actual := filepath, r.URL.Path; expected != actual {
			t.Errorf("request url: expected=%v actual=%v", expected, actual)
		}
		fmt.Fprintf(w, expected)
	}))
	defer server.Close()
	client := &Client{}
	actual, err := client.getFile(context.Background(), server.URL+filepath)
	if expected, actual := expected, string(actual); expected != actual {
		t.Fatalf("expected=%v actual=%v", expected, actual)
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientGetFile_FileDoesNotExist_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	client := &Client{}
	if _, err := client.getFile(context.Background(), server.URL); err == nil {
		t.Fatal("expected error when file doesn't exist")
	}
}

func TestClientGetReleaseFromInRelease_PresentAndValidSignature_NoError(t *testing.T) {
	inRelease, release, _, keyRing := newTestKeyRingAndRelease()
	client := &Client{KeyRing: keyRing}
	client.testhookGetFile = getFileInRelease(t, inRelease)
	actual, err := client.getReleaseFromInRelease(context.Background(), "InRelease")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expected, actual := release, actual; !reflect.DeepEqual(expected, actual) {
		t.Fatalf("expected=%v actual=%v", expected, actual)
	}
}

func TestClientGetReleaseFromInRelease_PresentButInvalidSignature_ReturnsError(t *testing.T) {
	inRelease, _, _, _ := newTestKeyRingAndRelease()
	client := &Client{KeyRing: newTestKeyRingEmpty()}
	client.testhookGetFile = getFileInRelease(t, inRelease)
	_, err := client.getReleaseFromInRelease(context.Background(), "InRelease")
	if err == nil {
		t.Fatal("expected error on signature failure")
	}
}

func TestClientGetReleaseFromFilePair_BothPresentAndValidSignature_NoError(t *testing.T) {
	_, release, releaseGPG, keyRing := newTestKeyRingAndRelease()
	client := &Client{KeyRing: keyRing}
	client.testhookGetFile = getFileByFilePair(t, release, releaseGPG)
	actual, err := client.getReleaseFromFilePair(context.Background(), "Release", "Release.gpg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expected, actual := release, actual; !reflect.DeepEqual(expected, actual) {
		t.Fatalf("expected=%v actual=%v", expected, actual)
	}
}

func TestClientGetReleaseFromFilePair_InvalidSignature_ReturnsError(t *testing.T) {
	_, release, releaseGPG, _ := newTestKeyRingAndRelease()
	client := &Client{KeyRing: newTestKeyRingEmpty()}
	client.testhookGetFile = getFileByFilePair(t, release, releaseGPG)
	if _, err := client.getReleaseFromFilePair(context.Background(), "Release", "Release.gpg"); err == nil {
		t.Fatal("expected error on signature failure")
	}
}

func getFileInRelease(t *testing.T, inRelease []byte) func(context.Context, string) ([]byte, error) {
	return func(ctx context.Context, url string) ([]byte, error) {
		if url != "InRelease" {
			t.Errorf("unexpected url to test getfile: %v", url)
			return nil, errors.Errorf("unexpected url to test getfile: %v", url)
		}
		return inRelease, nil
	}
}

func getFileByFilePair(t *testing.T, release, releaseGPG []byte) func(context.Context, string) ([]byte, error) {
	return func(ctx context.Context, url string) ([]byte, error) {
		if url == "Release" {
			return release, nil
		} else if url == "Release.gpg" {
			return releaseGPG, nil
		} else {
			t.Errorf("unexpected url to test getfile: %v", url)
			return nil, errors.Errorf("unexpected url to test getfile: %v", url)
		}
	}
}

func newTestValidClient() *Client {
	return &Client{
		KeyRing:      newTestKeyRing(),
		Architecture: "amd64",
	}
}

func newTestKeyRing() KeyRing {
	return &testKeyRing{testGenerateEntityList()}
}

func newTestKeyRingEmpty() KeyRing {
	return &testKeyRing{openpgp.EntityList{}}
}

type testKeyRing struct {
	el openpgp.EntityList
}

func (tkr *testKeyRing) KeyRing() openpgp.KeyRing {
	return tkr.el
}

func newTestKeyRingAndRelease() (inRelease, release, releaseGPG []byte, keyRing KeyRing) {
	el := testGenerateEntityList()
	key := el[0].PrivateKey
	keyRing = &testKeyRing{el}
	release = []byte("Release File Contents\n")

	inReleaseBuf := &bytes.Buffer{}
	inReleaseW, err := clearsign.Encode(inReleaseBuf, key, nil)
	if err != nil {
		panic(err)
	}
	if _, err := inReleaseW.Write(release); err != nil {
		panic(err)
	}
	if err := inReleaseW.Close(); err != nil {
		panic(err)
	}
	inRelease = inReleaseBuf.Bytes()

	releaseGPGBuf := &bytes.Buffer{}
	if err := openpgp.ArmoredDetachSign(releaseGPGBuf, el[0], bytes.NewBuffer(release), nil); err != nil {
		panic(err)
	}
	releaseGPG = releaseGPGBuf.Bytes()
	return
}

func testGenerateEntityList() openpgp.EntityList {
	e, err := openpgp.NewEntity("name", "comment", "email@example.com", nil)
	if err != nil {
		panic(err)
	}
	for _, id := range e.Identities {
		if err := id.SelfSignature.SignUserId(id.UserId.Id, e.PrimaryKey, e.PrivateKey, nil); err != nil {
			panic(err)
		}
	}
	return openpgp.EntityList{e}
}
