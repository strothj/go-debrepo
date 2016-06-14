package debrepo

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"golang.org/x/net/context"
)

const (
	// ErrInvalidRepository is returned from ParseRepository() when entry is not
	// in the format
	// "deb http://ftp.debian.org/debian squeeze main contrib non-free".
	ErrInvalidRepository = Error("unable to parse source")
)

// RepositoryList is a list of Debian package repositories.
type RepositoryList []*Repository

// Repository represents a Debian package repository.
type Repository struct {
	repoType     string
	baseURI      string
	distribution string
	components   []string
}

// ParseRepository parses entry to create a Repository.
// Entry must be in the format:
// 	deb http://ftp.debian.org/debian squeeze main contrib non-free
func ParseRepository(entry string) (*Repository, error) {
	ss := strings.Split(entry, " ")
	if len(ss) < 4 {
		return nil, ErrInvalidRepository
	}
	for _, field := range ss {
		if len(field) == 0 {
			return nil, ErrInvalidRepository
		}
	}
	if ss[0] != "deb" && ss[0] != "deb-src" {
		return nil, ErrInvalidRepository
	}
	if !isURL(ss[1]) {
		return nil, ErrInvalidRepository
	}
	return &Repository{
		repoType:     ss[0],
		baseURI:      ss[1],
		distribution: ss[2],
		components:   ss[3:],
	}, nil
}

// String returns the value of Repository as a string in the form found in a
// source.list file:
// 	deb http://ftp.debian.org/debian squeeze main contrib non-free
func (r Repository) String() string {
	if len(r.components) == 0 {
		return ""
	}
	return fmt.Sprintf("%s %s %s %s",
		r.repoType,
		r.baseURI,
		r.distribution,
		strings.Join(r.components, " "))
}

// isZero returns true if Repository is empty.
func (r Repository) isZero() bool {
	return len(r.baseURI) == 0
}

// InReleaseURL returns the URL to the repository's InRelease file.
func (r Repository) InReleaseURL() string {
	u, err := url.Parse(r.baseURI)
	if err != nil {
		panic(err)
	}
	u.Path = path.Join(u.Path, "dists", r.distribution, "InRelease")
	return u.String()
}

// ReleaseURL returns the URL to the repository's InRelease file.
func (r Repository) ReleaseURL() string {
	u, err := url.Parse(r.baseURI)
	if err != nil {
		panic(err)
	}
	u.Path = path.Join(u.Path, "dists", r.distribution, "Release")
	return u.String()
}

// ReleaseGPGURL returns the URL to the repository's Release.gpg file.
func (r Repository) ReleaseGPGURL() string {
	u, err := url.Parse(r.baseURI)
	if err != nil {
		panic(err)
	}
	u.Path = path.Join(u.Path, "dists", r.distribution, "Release.gpg")
	return u.String()
}

// GetRelease downloads the release file and its associated signature file.
// If client is nil, http.DefaultClient is used.
func (r *Repository) GetRelease(ctx context.Context, client *http.Client) (*Release, error) {
	return GetRelease(ctx, client, r)
}
