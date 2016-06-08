package debrepo

import (
	"reflect"
	"testing"
)

var readFieldTests = []struct {
	input    string
	expected Fields
}{
	{
		input: `Origin: Debian
Components: main contrib non-free
MD5Sum:
 974c021c888f99cdfe9562e5f952484a  1194721 contrib/Contents-amd64
 450dd45dc5f77c017ef8dd3dd7bc0f8c    88515 contrib/Contents-amd64.gz`,
		expected: Fields{
			"Origin":     {"Debian"},
			"Components": {"main contrib non-free"},
			"Md5sum":     {"974c021c888f99cdfe9562e5f952484a  1194721 contrib/Contents-amd64 450dd45dc5f77c017ef8dd3dd7bc0f8c    88515 contrib/Contents-amd64.gz"},
		},
	},
	{
		input: `Description-md5: fcb68fdad0dca137e47a44b011e92ee4
Tag: implemented-in::c, interface::daemon, network::server, network::service,
 protocol::http, role::program, use::proxying`,
		expected: Fields{
			"Description-Md5": {"fcb68fdad0dca137e47a44b011e92ee4"},
			"Tag":             {"implemented-in::c, interface::daemon, network::server, network::service, protocol::http, role::program, use::proxying"},
		},
	},
}

func TestReadFields(t *testing.T) {
	for i, test := range readFieldTests {
		actual, err := ReadFields([]byte(test.input))
		if err != nil {
			t.Fatalf("test(%v): unexpected error parsing fields: %v", i, err)
		}
		if expected := test.expected; !reflect.DeepEqual(expected, actual) {
			t.Fatalf("test(%v): expected != actual", i)
		}
	}
}
