package feedauth

import (
	"net/http"
	"sync"

	"github.com/menta2k/siem-v2/backend/internal/ingest"
	"github.com/menta2k/siem-v2/backend/internal/ingest/logpush"
	"github.com/menta2k/siem-v2/backend/internal/ingest/vectorhttp"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// Handler serves the per-feed ingest routes: /ingest/v1/{provider}/{feedID}.
//
// It authenticates against the Store first and only then hands the request to
// the provider's receiver, so the receivers stay ignorant of the feed model.
// Ported from v1's per-feed endpoints; the URL shape is kept identical so
// v1's provider-configuration documentation transfers verbatim.
type Handler struct {
	Store        *Store
	Buffer       ingest.Buffer
	MaxBodyBytes int64
	// OnAccepted, when set, observes each authenticated delivery — the hook
	// health registration attaches to.
	OnAccepted func(feed Feed)

	mu        sync.Mutex
	receivers map[string]http.Handler
}

// Mount registers the feed routes on a mux. PUT exists because Cloudflare
// validates a Logpush destination with a PUT and a 405 would block job
// creation (v1 lesson).
func (h *Handler) Mount(mux *http.ServeMux) {
	mux.Handle("POST /ingest/v1/{provider}/{feedID}", h)
	mux.Handle("PUT /ingest/v1/{provider}/{feedID}", h)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	feedID := r.PathValue("feedID")

	feed, verdict := h.Store.Check(provider, feedID, credentialFrom(r))
	switch verdict {
	case Unavailable:
		// Our fault, not the sender's: senders back off and retry a 503,
		// while a 401 would make them drop the batch or disable the job.
		http.Error(w, "credential store unavailable", http.StatusServiceUnavailable)
		return
	case Denied:
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if h.OnAccepted != nil {
		h.OnAccepted(feed)
	}
	h.receiverFor(feed).ServeHTTP(w, r)
}

// credentialFrom prefers the Authorization header; the token query parameter
// is the documented fallback for senders with no custom-header field.
func credentialFrom(r *http.Request) string {
	if tok := ingest.BearerToken(r.Header.Get("Authorization")); tok != "" {
		return tok
	}
	return r.URL.Query().Get("token")
}

// receiverFor builds (once) the provider receiver bound to this feed's
// identity. Authentication already happened here, so the receiver's own check
// is pinned open.
func (h *Handler) receiverFor(feed Feed) http.Handler {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.receivers == nil {
		h.receivers = map[string]http.Handler{}
	}
	if rec, ok := h.receivers[feed.ID]; ok {
		return rec
	}
	authenticated := ingest.Authenticator(func(string) bool { return true })
	var rec http.Handler
	if feed.Provider == string(schema.ProviderCloudflare) {
		rec = &logpush.Receiver{
			Buffer: h.Buffer, Authenticate: authenticated,
			Tenant: feed.TenantID, SourceID: feed.ID, MaxBodyBytes: h.MaxBodyBytes,
		}
	} else {
		rec = &vectorhttp.Receiver{
			Buffer: h.Buffer, Authenticate: authenticated,
			Tenant: feed.TenantID, SourceID: feed.ID,
			Provider: schema.Provider(feed.Provider), MaxBodyBytes: h.MaxBodyBytes,
		}
	}
	h.receivers[feed.ID] = rec
	return rec
}
