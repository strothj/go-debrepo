package debrepo

import "runtime"

// archMap is a mapping between Go architecture strings and those accepted by
// Debian package repositories.
//                Go     repo
var archMap = map[string]string{
	"amd64": "amd64",
	"arm64": "arm64",
	"386":   "i386",
}

func detectArchitecture() string {
	return archMap[runtime.GOARCH]
}
