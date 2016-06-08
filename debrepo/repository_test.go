package debrepo

import (
	"reflect"
	"testing"
)

var sourceTests = []struct {
	entry  string
	source *Repository
	str    string
	err    error
}{
	{
		entry: "deb http://ftp.debian.org/debian squeeze main contrib non-free",
		source: &Repository{
			repoType:     "deb",
			baseURI:      "http://ftp.debian.org/debian",
			distribution: "squeeze",
			components:   []string{"main", "contrib", "non-free"},
		},
		str: "deb http://ftp.debian.org/debian squeeze main contrib non-free",
		err: nil,
	},
	{
		entry: "deb-src http://us.archive.ubuntu.com/ubuntu/ saucy universe",
		source: &Repository{
			repoType:     "deb-src",
			baseURI:      "http://us.archive.ubuntu.com/ubuntu/",
			distribution: "saucy",
			components:   []string{"universe"},
		},
		str: "deb-src http://us.archive.ubuntu.com/ubuntu/ saucy universe",
		err: nil,
	},
	{
		entry:  "deb-invalid http://us.archive.ubuntu.com/ubuntu/ saucy universe",
		source: nil,
		str:    "",
		err:    ErrInvalidRepository,
	},
	{
		entry:  "deb http://us.archive.ubuntu.com/ubuntu/ saucy  ", // extra whitespace
		source: nil,
		str:    "",
		err:    ErrInvalidRepository,
	},
	{
		entry:  "deb #notURL saucy universe",
		source: nil,
		str:    "",
		err:    ErrInvalidRepository,
	},
}

func TestRepository_ParseRepository(t *testing.T) {
	for i, tt := range sourceTests {
		source, err := ParseRepository(tt.entry)
		if expected, actual := tt.source, source; !reflect.DeepEqual(expected, actual) {
			t.Fatalf("test(%v): source: expected=%v actual=%v", i, expected, actual)
		}
		if expected, actual := tt.err, err; !reflect.DeepEqual(expected, actual) {
			t.Fatalf("test(%v): error: expected=%v actual=%v", i, expected, actual)
		}
	}
}

func TestRepository_String(t *testing.T) {
	for i, tt := range sourceTests {
		var str string
		if tt.source != nil {
			str = tt.source.String()
		} else {
			str = ""
		}
		if expected, actual := tt.str, str; expected != actual {
			t.Fatalf("test(%v): expected=%v actual=%v", i, expected, actual)
		}
	}
}

func TestRepository_EmptyRepository_StringReturnsEmptyString(t *testing.T) {
	if expected, actual := "", (Repository{}).String(); expected != actual {
		t.Fatalf("expected=\"%s\" actual=\"%s\"", expected, actual)
	}
}

func TestRepository_ReleaseURL(t *testing.T) {
	r := &Repository{
		baseURI:      "http://ftp.debian.org/debian",
		distribution: "squeeze",
	}
	expected, actual := "http://ftp.debian.org/debian/dists/squeeze/InRelease", r.InReleaseURL()
	if expected != actual {
		t.Fatalf("expected=%s actual=%s", expected, actual)
	}
}
