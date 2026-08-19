// Package version carries the build identity stamped at link time.
//
// The variables are set via -ldflags "-X ..." by the release workflow and the
// backend Dockerfile. Their defaults are deliberately honest: a binary built
// without stamping reports "dev", never a borrowed version number. The release
// workflow greps the built binary for the version string, because -X against a
// missing symbol is silently ignored — an unstamped binary looks exactly like
// a successful build.
package version

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// String renders the identity for startup logs and health output.
func String() string { return Version + " (" + Commit + " " + Date + ")" }
