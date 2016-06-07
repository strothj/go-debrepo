package debrepo

import (
	"bytes"
	"fmt"
	"net/http"

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
