package ingest

// Authenticator decides whether a presented ingest credential is acceptable.
//
// The static shared-secret deployment and the per-feed token store both hide
// behind this one function: receivers stay ignorant of where credentials live,
// and swapping the model is wiring, not surgery. Implementations MUST compare
// in constant time and MUST fail closed when their backing state is empty.
type Authenticator func(presented string) bool

// StaticSecret authenticates against one fixed credential — the original
// shared-secret model, kept for single-tenant and test deployments.
func StaticSecret(secret string) Authenticator {
	return func(presented string) bool {
		return AuthenticateSecret(presented, secret)
	}
}
