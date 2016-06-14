package debrepo

import (
	"bytes"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/net/context"
	"golang.org/x/net/context/ctxhttp"
)

// KeyRing returns a OpenPGP keyring. It is used by Client to verify the
// authenticity of Release files on package repositories.
type KeyRing interface {
	KeyRing() openpgp.KeyRing
}

// A Client is a package repository client. It is used to retrieve packages from
// Debian style archive repositories.
//
// KeyRing must not be nil. It is used to verify the authenticity of files on
// the repository.
//
// Architecture must be set to a supported architecture. See ListArchitectures
// and ValidateArchitecture.
//
// If HTTPClient is nil, http.DefaultClient is used.
type Client struct {
	HTTPClient      *http.Client
	KeyRing         KeyRing
	Architecture    string
	testhookGetFile func(context.Context, string) ([]byte, error)
}

// GetReleaseIndex returns the contents of the Release file corresponding to
// the distribution in repo. It returns an error if the Release file
// fails the OpenPGP signature check.
func (c *Client) GetReleaseIndex(ctx context.Context, repo *Repository) ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if repo == nil || repo.isZero() {
		return nil, errors.New("empty repo provided")
	}
	release, err := c.getReleaseFromInRelease(ctx, repo.InReleaseURL())
	if err == nil {
		return release, nil
	}
	return c.getReleaseFromFilePair(ctx, repo.ReleaseURL(), repo.ReleaseGPGURL())
}

// GetPackageIndexes returns Files which can be used to read the contents of the
// specified package indexes.
func (c *Client) GetPackageIndexes(ctx context.Context, repo *Repository, release *Release) ([]*File, error) {
	panic("Not Implemented")
}

func (c *Client) validate() error {
	if c.KeyRing == nil {
		return errors.New("keyring nil")
	}
	return ValidateArchitecture(c.Architecture)
}

func (c *Client) getFile(ctx context.Context, url string) ([]byte, error) {
	if c.testhookGetFile != nil {
		return c.testhookGetFile(ctx, url)
	}
	resp, err := ctxhttp.Get(ctx, c.HTTPClient, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("failed to get remote file: %s: %s", url, resp.Status)
	}
	return ioutil.ReadAll(resp.Body)
}

func (c *Client) getReleaseFromInRelease(ctx context.Context, inReleaseURL string) ([]byte, error) {
	b, err := c.getFile(ctx, inReleaseURL)
	if err != nil {
		return nil, err
	}
	block, _ := clearsign.Decode(b)
	bb := bytes.NewBuffer(block.Bytes)
	if _, err := openpgp.CheckDetachedSignature(c.KeyRing.KeyRing(), bb, block.ArmoredSignature.Body); err != nil {
		return nil, errors.Wrap(err, "InRelease file failed signature check")
	}
	return block.Plaintext, nil
}

func (c *Client) getReleaseFromFilePair(ctx context.Context, releaseURL, releaseGPGURL string) ([]byte, error) {
	b, err := c.getFile(ctx, releaseURL)
	if err != nil {
		return nil, err
	}
	block := &clearsign.Block{Plaintext: b}

	b, err = c.getFile(ctx, releaseGPGURL)
	if err != nil {
		return nil, err
	}
	block.ArmoredSignature, err = armor.Decode(bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	bb := bytes.NewBuffer(block.Plaintext)
	if _, err := openpgp.CheckDetachedSignature(c.KeyRing.KeyRing(), bb, block.ArmoredSignature.Body); err != nil {
		return nil, errors.Wrap(err, "Release file failed signature check")
	}
	return block.Plaintext, nil
}
