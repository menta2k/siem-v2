//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/data/postgres"
	"github.com/menta2k/siem-v2/backend/internal/service"
)

// TestBootstrapAdmin exercises the first-start path against a genuinely empty
// database: a bootstrap invite is issued while nobody can sign in, re-issued
// on restart until redeemed (a lost link must not mean a locked-out
// deployment), and never issued again once a password exists.
func TestBootstrapAdmin(t *testing.T) {
	ctx := context.Background()
	admin, err := postgres.Connect(ctx, dsn(), 2, 1)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer admin.Close()

	dbName := fmt.Sprintf("bootstrap_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatalf("create scratch db: %v", err)
	}
	defer func() { _, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+dbName) }()

	scratchDSN := strings.Replace(dsn(), "/siem?", "/"+dbName+"?", 1)
	pool, err := postgres.Connect(ctx, scratchDSN, 2, 1)
	if err != nil {
		t.Fatalf("connect scratch: %v", err)
	}
	defer pool.Close()
	if err := postgres.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate scratch: %v", err)
	}

	principals := postgres.NewPrincipalRepo(pool)
	authRepo := postgres.NewAuthRepo(pool)
	boot := func() (string, bool) {
		tok, issued, err := service.BootstrapAdmin(ctx, principals, authRepo,
			"root@example.com", "default", time.Now)
		if err != nil {
			t.Fatalf("bootstrap: %v", err)
		}
		return tok, issued
	}

	tok1, issued := boot()
	if !issued || tok1 == "" {
		t.Fatal("an empty database is exactly first start: an invite must be issued")
	}

	// "Restart" while unredeemed: re-issue, and the OLD link must be dead —
	// otherwise a link scraped from old logs stays live indefinitely.
	tok2, issued := boot()
	if !issued || tok2 == tok1 {
		t.Fatal("an unredeemed bootstrap must re-issue a fresh link on restart")
	}

	svc := &service.AuthService{Repo: authRepo}
	redeem := func(tok string) int {
		rec := doPublic(t, svc.RedeemInvite, `{"token":"`+tok+`","password":"a very long bootstrap pass"}`)
		return rec.Code
	}
	if code := redeem(tok1); code == 200 {
		t.Fatal("the superseded link must not redeem")
	}
	if code := redeem(tok2); code != 200 {
		t.Fatalf("the current link must redeem, got %d", code)
	}

	// A password now exists: bootstrap must become a permanent no-op.
	if _, issued := boot(); issued {
		t.Fatal("once someone can sign in, bootstrap must never issue again")
	}

	rec, err := authRepo.ByEmail(ctx, "root@example.com")
	if err != nil || rec.PasswordHash == "" || rec.Role != "admin" || !rec.Active {
		t.Fatalf("bootstrap admin not usable: %+v err=%v", rec, err)
	}
}

func doPublic(t *testing.T, h func(http.ResponseWriter, *http.Request), body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invites/redeem", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}
