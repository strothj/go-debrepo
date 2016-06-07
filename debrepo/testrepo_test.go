package debrepo

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"reflect"
	"testing"

	"bytes"

	"golang.org/x/crypto/openpgp"
)

func TestTestRepository_KeyRing(t *testing.T) {
	ts := NewTestRepository()
	ts.Close()
	keyring := ts.KeyRing()
	if len(keyring) == 0 {
		t.Fatal("expected keyring not empty")
	}
}

func TestTestRepository_Get(t *testing.T) {
	ts := NewTestRepository()
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/ubuntu/dists/xenial/InRelease")
	if err != nil {
		t.Fatalf("unexpected error getting file: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %v: %s", resp.StatusCode, resp.Status)
	}
	actual, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	expected, _ := ioutil.ReadFile("testdata/test_repo/ubuntu/dists/xenial/InRelease")
	if !reflect.DeepEqual(expected, actual) {
		t.Fatal("returned file does not match expected")
	}
}

func TestTestRepository_BlockFile(t *testing.T) {
	ts := NewTestRepository()
	defer ts.Close()
	ts.BlockFile("InRelease")
	resp, _ := http.Get(ts.URL + "/ubuntu/dists/xenial/InRelease")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected status 404, got: %v", resp.StatusCode)
	}
}

type testRepository struct {
	*httptest.Server
	blockFilename string
}

func NewTestRepository() *testRepository {
	tr := &testRepository{}
	mux := http.NewServeMux()
	mux.Handle("/ubuntu/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if path.Base(r.URL.Path) == tr.blockFilename {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		http.FileServer(http.Dir("testdata/test_repo/")).ServeHTTP(w, r)
	}))
	tr.Server = httptest.NewServer(mux)
	return tr
}

func (tr *testRepository) BlockFile(filename string) {
	tr.blockFilename = filename
}

func (tr *testRepository) KeyRing() openpgp.EntityList {
	path := "testdata/ubuntu-keyring_2012.05.19/keyrings"
	files, err := ioutil.ReadDir(path)
	if err != nil {
		panic(err)
	}
	buf := &bytes.Buffer{}
	for _, file := range files {
		f, err := os.Open(path + "/" + file.Name())
		if err != nil {
			panic(err)
		}
		defer f.Close()
		_, err = buf.ReadFrom(f)
		if err != nil {
			panic(err)
		}
	}
	el, err := openpgp.ReadKeyRing(buf)
	if err != nil {
		panic(err)
	}
	return el
}

func (tr *testRepository) Repository() *Repository {
	r, _ := ParseRepository("deb " + tr.URL + "/ubuntu xenial main")
	return r
}
