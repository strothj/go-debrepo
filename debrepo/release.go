package debrepo

import (
	"bufio"
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"io/ioutil"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/net/context"
	"golang.org/x/net/context/ctxhttp"
)

var (
	nop                             = func() {}
	testhookGetReleaseFromInRelease = nop
	testhookGetReleaseFromRelease   = nop
)

// Release fields corresponding to the release file table.
const (
	ReleaseFieldMD5Sum = "Md5sum"
	ReleaseFieldSHA1   = "Sha1"
	ReleaseFieldSHA256 = "Sha256"
)

// Release contains a listing of index files for the distribution and their
// associated hashes.
type Release clearsign.Block

// GetRelease downloads the release file and its associated signature file.
// If client is nil, http.DefaultClient is used.
func GetRelease(ctx context.Context, client *http.Client, repo *Repository) (*Release, error) {
	// prevent race conditions during testing
	testhookGetReleaseFromInRelease := testhookGetReleaseFromInRelease
	testhookGetReleaseFromRelease := testhookGetReleaseFromRelease

	getFile := func(url string) ([]byte, error) {
		resp, err := ctxhttp.Get(ctx, client, url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to get file: %s: %s", url, resp.Status)
		}
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return b, nil
	}
	var block *clearsign.Block

	b, err := getFile(repo.InReleaseURL())
	if err == nil {
		block, _ = clearsign.Decode(b)
		if len(block.Plaintext) != 0 && block.ArmoredSignature != nil {
			testhookGetReleaseFromInRelease()
			return (*Release)(block), nil
		}
	}

	testhookGetReleaseFromRelease()
	b, err = getFile(repo.ReleaseURL())
	if err != nil {
		return nil, err
	}
	block = new(clearsign.Block)
	block.Plaintext = b

	b, err = getFile(repo.ReleaseGPGURL())
	if err != nil {
		return nil, err
	}
	block.ArmoredSignature, err = armor.Decode(bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	return (*Release)(block), nil
}

// CheckSignature returns the signer of the release file if it is valid. If the
// signer isn't known, ErrUnknownIssuer (golang.org/x/crypto/openpgp/errors) is
// returned.
func (r *Release) CheckSignature(keyring openpgp.KeyRing) (signer *openpgp.Entity, err error) {
	var b *bytes.Buffer
	if len(r.Bytes) > 0 {
		b = bytes.NewBuffer(r.Bytes)
	} else {
		b = bytes.NewBuffer(r.Plaintext)
	}
	return openpgp.CheckDetachedSignature(keyring, b, r.ArmoredSignature.Body)
}

// ReadFields reads the key/value fields from the Release file.
func (r *Release) ReadFields() (Fields, error) {
	return ReadFields(r.Plaintext)
}

// ReadFileTable returns a map containing the index files present on the package
// repository. The keys are the paths of the files relative to the directory of
// the Release file. The values contain meta information describing which
// checksum function was used, checksum value, and the file size.
func (r *Release) ReadFileTable() (map[string]FileMeta, error) {
	fields, err := r.ReadFields()
	if err != nil {
		return nil, err
	}

	fileTable := make(map[string]FileMeta)
	err = parseFileTable(fileTable, fields[ReleaseFieldMD5Sum][0], crypto.MD5)
	err = parseFileTable(fileTable, fields[ReleaseFieldSHA1][0], crypto.SHA1)
	err = parseFileTable(fileTable, fields[ReleaseFieldSHA256][0], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return fileTable, nil
}

func parseFileTable(fileTable map[string]FileMeta, table string, hash crypto.Hash) error {
	buf := bytes.NewBuffer([]byte(table))
	scanner := bufio.NewScanner(buf)
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		hashBytes, err := hex.DecodeString(scanner.Text())
		if err != nil {
			return err
		}
		if len(hashBytes) != hash.Size() {
			return errors.New("invalid hash string in release file table")
		}
		if !scanner.Scan() {
			return errors.New("missing file size in release file table")
		}
		size, err := strconv.ParseInt(scanner.Text(), 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse file size in release file table: %v", err)
		}
		if size < 0 {
			return errors.New("file size in release file table is negative")
		}
		if !scanner.Scan() {
			return errors.New("missing file name in release file table")
		}
		filepath := scanner.Text()
		fileTable[filepath] = FileMeta{
			HashSum: hashBytes,
			Hash:    hash,
			Size:    size,
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}
