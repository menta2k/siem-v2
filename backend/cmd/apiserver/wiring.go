// Wiring that is setup rather than serving: development seed data and the
// authentication stack's construction. Split from main.go to keep each file
// within the constitution's size limit and each concern findable.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/menta2k/siem-v2/backend/internal/asnowner"
	authpkg "github.com/menta2k/siem-v2/backend/internal/auth"
	"github.com/menta2k/siem-v2/backend/internal/biz/tenancy"
	"github.com/menta2k/siem-v2/backend/internal/conf"
	"github.com/menta2k/siem-v2/backend/internal/data/postgres"
	datavalkey "github.com/menta2k/siem-v2/backend/internal/data/valkey"
	"github.com/menta2k/siem-v2/backend/internal/server"
	"github.com/menta2k/siem-v2/backend/internal/service"
	valkeygo "github.com/valkey-io/valkey-go"
)

// seedDev creates the development tenants and principals.
//
// Two tenants are seeded on purpose: a single-tenant deployment cannot
// demonstrate isolation, and isolation that is never exercised is isolation
// nobody has checked.
func (s *apiServer) seedDev(ctx context.Context) error {
	for _, t := range []struct{ id, name string }{{"acme", "Acme Corp"}, {"globex", "Globex Inc"}} {
		if err := s.principals.EnsureTenant(ctx, t.id, t.name, 0, 0); err != nil {
			return err
		}
	}
	people := []*tenancy.Principal{
		{ID: "acme-analyst", TenantID: "acme", Identity: "analyst@acme.example.com", Role: tenancy.RoleAnalyst, Active: true},
		{ID: "acme-engineer", TenantID: "acme", Identity: "engineer@acme.example.com", Role: tenancy.RoleEngineer, Active: true},
		{ID: "acme-admin", TenantID: "acme", Identity: "admin@acme.example.com", Role: tenancy.RoleAdmin, Active: true},
		{ID: "globex-analyst", TenantID: "globex", Identity: "analyst@globex.example.com", Role: tenancy.RoleAnalyst, Active: true},
	}
	for _, p := range people {
		if err := s.principals.Upsert(ctx, p); err != nil {
			return err
		}
	}

	// Development passwords, set only when the env var is present so a real
	// deployment cannot accidentally ship seeded credentials.
	if devPassword := os.Getenv("SIEM_DEV_SEED_PASSWORD"); devPassword != "" {
		authRepo := postgres.NewAuthRepo(s.pool)
		hash, err := authpkg.HashPassword(devPassword)
		if err != nil {
			return err
		}
		for _, p := range people {
			if err := authRepo.SetPassword(ctx, p.ID, hash); err != nil {
				return err
			}
		}
		s.logger.Warn("DEV MODE: seeded principals share the dev password")
	}

	// The four sources this deployment collects from. Cadence is what makes
	// silence detectable, so every source declares one.
	sources := []postgres.SourceRow{
		{ID: "cf-1", Provider: "cloudflare", DeliveryMode: "push", ExpectedCadenceSeconds: 900,
			DataClassification: "standard", ParserVersion: "cloudflare/1.0",
			DetectionPosture: "pipeline.source_silence, pipeline.parse_failure_spike",
			Enabled:          true, HealthState: "awaiting_first_record"},
		{ID: "dd-1", Provider: "datadome", DeliveryMode: "pull", ExpectedCadenceSeconds: 900,
			DataClassification: "standard", ParserVersion: "datadome/1.0",
			DetectionPosture: "pipeline.source_silence",
			Enabled:          true, HealthState: "awaiting_first_record"},
		{ID: "f5-1", Provider: "f5asm", DeliveryMode: "push", ExpectedCadenceSeconds: 900,
			DataClassification: "sensitive", ParserVersion: "f5asm/1.0",
			DetectionPosture: "pipeline.source_silence",
			Enabled:          true, HealthState: "awaiting_first_record"},
		{ID: "ngx-1", Provider: "nginx", DeliveryMode: "push", ExpectedCadenceSeconds: 900,
			DataClassification: "standard", ParserVersion: "nginx/1.0",
			DetectionPosture: "none: origin access logs carry no independent verdict",
			Enabled:          true, HealthState: "awaiting_first_record"},
	}
	for _, src := range sources {
		if err := s.sources.Upsert(ctx, "acme", src); err != nil {
			return err
		}
	}
	return nil
}

// buildAuthService wires tokens, sealing and revocation.
//
// Both keys come from the environment, never configuration files (FR-057). The
// service refuses to start without them: an auth stack that silently fell back
// to a default key would mint tokens anyone could forge.
func buildAuthService(cfg *conf.Config, pool *pgxpool.Pool, logger *slog.Logger) (*service.AuthService, error) {
	jwtKey := os.Getenv("SIEM_JWT_KEY")
	if len(jwtKey) < 32 {
		return nil, fmt.Errorf("SIEM_JWT_KEY must be set to at least 32 bytes")
	}
	mfaKey := os.Getenv("SIEM_MFA_KEY")
	if len(mfaKey) != authpkg.SealerKeyBytes {
		return nil, fmt.Errorf("SIEM_MFA_KEY must be exactly %d bytes", authpkg.SealerKeyBytes)
	}
	sealer, err := authpkg.NewSealer([]byte(mfaKey))
	if err != nil {
		return nil, err
	}

	vk, err := valkeygo.NewClient(valkeygo.ClientOption{InitAddress: cfg.Storage.Valkey.Addrs})
	if err != nil {
		return nil, fmt.Errorf("valkey for revocations: %w", err)
	}
	revocations := datavalkey.NewRevocations(vk)

	issuer, err := authpkg.NewTokenIssuer(jwtKey, 10*time.Minute, 7*24*time.Hour, revocations)
	if err != nil {
		return nil, err
	}

	authRepo := postgres.NewAuthRepo(pool)
	svc := &service.AuthService{
		Repo:   authRepo,
		Tokens: issuer,
		Sealer: sealer,
		Issuer: "SIEM v2",
		// 10 attempts per minute per identity: slow enough to make online
		// guessing useless, without a hard lockout an attacker could weaponise
		// against a known email.
		Limiter:            server.NewRateLimiter(10, time.Minute),
		DevInsecureCookies: os.Getenv("SIEM_DEV_INSECURE_COOKIES") == "true",
		DevSkipMFA:         os.Getenv("SIEM_DEV_SKIP_MFA") == "true",
	}
	if svc.DevInsecureCookies {
		logger.Warn("DEV MODE: refresh cookies are not Secure; never run production this way")
	}
	if svc.DevSkipMFA {
		logger.Warn("DEV MODE: MFA is skipped at login; never run production this way")
	}
	return svc, nil
}

// startASNOwnerWorker begins the daily attribution refresh unless disabled.
//
// Enabled by default (v1's choice): the table is public registry data and a
// failed download only leaves AS numbers bare. SIEM_ASN_OWNERS_ENABLED=false
// turns it off for air-gapped deployments; SIEM_ASN_OWNERS_SOURCE_URL and
// SIEM_ASN_OWNERS_REFRESH_HOURS override the source and cadence.
func startASNOwnerWorker(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) {
	if os.Getenv("SIEM_ASN_OWNERS_ENABLED") == "false" {
		logger.Info("asn owner refresh disabled by configuration")
		return
	}
	w := &asnowner.Worker{
		Source: postgres.NewASNOwnerRepo(pool),
		URL:    os.Getenv("SIEM_ASN_OWNERS_SOURCE_URL"),
		Logger: logger,
	}
	if h, err := strconv.Atoi(os.Getenv("SIEM_ASN_OWNERS_REFRESH_HOURS")); err == nil && h > 0 {
		w.Interval = time.Duration(h) * time.Hour
	}
	go w.Run(ctx)
}

// bootstrapAdmin seeds the first administrator when nobody can sign in.
//
// The one-time setup link goes to the LOG on purpose: at first start there is
// no signed-in admin, no configured mail, no channel at all except the
// operator's own terminal — and whoever reads this log already controls the
// deployment. The link expires, dies on redemption, and is re-issued fresh on
// every restart until someone completes setup.
func (s *apiServer) bootstrapAdmin(ctx context.Context) error {
	email := os.Getenv("SIEM_ADMIN_EMAIL")
	if email == "" {
		email = "admin@siem.local"
	}
	tenant := os.Getenv("SIEM_ADMIN_TENANT")

	token, issued, err := service.BootstrapAdmin(ctx,
		s.principals, postgres.NewAuthRepo(s.pool), email, tenant, time.Now)
	if err != nil {
		return err
	}
	if issued {
		s.logger.Warn("BOOTSTRAP: no account can sign in yet — open this one-time "+
			"setup link on the console to create the administrator's password",
			"email", email,
			"path", "/invite?token="+token,
			"expires_in", authpkg.DefaultInviteTTL.String())
	}
	return nil
}
