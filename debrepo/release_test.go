package debrepo

import (
	"crypto"
	"encoding/hex"
	"reflect"
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

func TestRelease_ReadFields(t *testing.T) {
	tr := NewTestRepository()
	defer tr.Close()
	release, _ := GetRelease(context.Background(), nil, tr.Repository())
	fields, err := release.ReadFields()
	if err != nil {
		t.Fatalf("unexpected error reading fields: %v", err)
	}
	if expected, actual := "Ubuntu", fields["Origin"][0]; expected != actual {
		t.Fatalf("field Origin: expected=%v actual=%v", expected, actual)
	}
}

func TestRelease_ReadFileTable(t *testing.T) {
	tr := NewTestRepository()
	defer tr.Close()
	release, _ := GetRelease(context.Background(), nil, tr.Repository())
	fileTable, err := release.ReadFileTable()
	if err != nil {
		t.Fatalf("unexpected error reading file table: %v", err)
	}
	if len(fileTable) < 800 {
		t.Fatalf("expected at least 800 files parsed, was: %v", len(fileTable))
	}
	if hash := fileTable["main/binary-amd64/Packages"].Hash; hash != crypto.SHA256 {
		t.Fatalf("expected hash type to be SHA256 when a SHA256 hash is present, was: %s", hash)
	}
}

var parseFileTableTests = []struct {
	table     string
	fileTable map[string]FileMeta
	valid     bool
}{
	{
		table: ` 974c021c888f99cdfe9562e5f952484a  1194721 contrib/Contents-amd64
 450dd45dc5f77c017ef8dd3dd7bc0f8c    88515 contrib/Contents-amd64.gz`,
		fileTable: map[string]FileMeta{
			"contrib/Contents-amd64": FileMeta{
				HashSum: decodeHexString("974c021c888f99cdfe9562e5f952484a"),
				Hash:    crypto.MD5,
				Size:    1194721,
			},
			"contrib/Contents-amd64.gz": FileMeta{
				HashSum: decodeHexString("450dd45dc5f77c017ef8dd3dd7bc0f8c"),
				Hash:    crypto.MD5,
				Size:    88515,
			},
		},
		valid: true,
	},
	{ // invalid character in hash
		table:     ` Z974c021c888f99cdfe9562e5f952484a  1194721 contrib/Contents-amd64`,
		fileTable: make(map[string]FileMeta),
		valid:     false,
	},
	{ // invalid hash size
		table:     ` 4c021c888f99cdfe9562e5f952484a  1194721 contrib/Contents-amd64`,
		fileTable: make(map[string]FileMeta),
		valid:     false,
	},
	{ // invalid file size character
		table:     ` 974c021c888f99cdfe9562e5f952484a  Z1194721 contrib/Contents-amd64`,
		fileTable: make(map[string]FileMeta),
		valid:     false,
	},
	{ // negative file size
		table:     ` 974c021c888f99cdfe9562e5f952484a  -1 contrib/Contents-amd64`,
		fileTable: make(map[string]FileMeta),
		valid:     false,
	},
	{ // missing field
		table:     ` 974c021c888f99cdfe9562e5f952484a  1194721 `,
		fileTable: make(map[string]FileMeta),
		valid:     false,
	},
	{ // missing fields
		table:     ` 974c021c888f99cdfe9562e5f952484a   `,
		fileTable: make(map[string]FileMeta),
		valid:     false,
	},
}

func TestParseFileTable(t *testing.T) {
	for i, test := range parseFileTableTests {
		actual := make(map[string]FileMeta)
		err := parseFileTable(actual, test.table, crypto.MD5)
		if expected, actual := test.valid, err == nil; expected != actual {
			t.Fatalf("test(%v): valid: expected=%v actual=%v", i, expected, actual)
		}
		if !reflect.DeepEqual(test.fileTable, actual) {
			t.Fatalf("test(%v): fileTable: \nexpected=%v\n \nactual=%v\n", i, test.fileTable, actual)
		}
	}
}

func decodeHexString(h string) []byte {
	b, _ := hex.DecodeString(h)
	return b
}
