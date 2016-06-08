package debrepo

import (
	"bufio"
	"bytes"
	"io"
	"net/textproto"
)

// Fields is a map of keys and values parsed from an index file.
type Fields textproto.MIMEHeader

// ReadFields returns a Fields containing the values parsed from the provided
// bytes. Field names are set by textproto.CanonicalMIMEHeaderKey().
//	From textproto.CanonicalMIMEHeaderKey:
//	The canonicalization converts the first letter and any letter following a
//	hyphen to upper case; the rest are converted to lowercase. For example, the
//	canonical key for "accept-encoding" is "Accept-Encoding". MIME header keys
//	are assumed to be ASCII only. If s contains a space or invalid header field
//	bytes, it is returned without modifications.
func ReadFields(b []byte) (Fields, error) {
	buf := bytes.NewBuffer(b)
	r := bufio.NewReader(buf)
	rr := textproto.NewReader(r)
	fields, err := rr.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return nil, err
	}
	return Fields(fields), nil
}
