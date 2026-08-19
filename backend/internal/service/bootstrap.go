package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/auth"
	"github.com/menta2k/siem-v2/backend/internal/biz/tenancy"
	"github.com/menta2k/siem-v2/backend/internal/data/postgres"
)

// BootstrapAdmin makes a fresh deployment reachable: when NO active principal
// can sign in with a password, it seeds an administrator and issues a one-time
// setup invite, returning the encoded token for the operator's log.
//
// Design decisions, in order of importance:
//
//   - No generated password. The operator sets their own through the ordinary
//     /invite flow, which also walks them into MFA enrolment at first login —
//     the bootstrap account gets no weaker path than any invited account.
//   - The condition is "nobody can sign in", not "first start". A deployment
//     whose only admin was deactivated recovers the same way it was born.
//   - While unredeemed, every restart RE-ISSUES (retiring the old link). The
//     alternative — honouring an open invite — means a lost link locks the
//     deployment out forever, which is strictly worse than the old log line
//     going stale.
func BootstrapAdmin(ctx context.Context,
	principals *postgres.PrincipalRepo, authRepo *postgres.AuthRepo,
	email, tenantID string, now func() time.Time,
) (token string, issued bool, err error) {

	usable, err := authRepo.AnyPasswordSet(ctx)
	if err != nil {
		return "", false, fmt.Errorf("bootstrap: %w", err)
	}
	if usable {
		return "", false, nil
	}

	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" || !strings.Contains(email, "@") {
		return "", false, fmt.Errorf("bootstrap: admin email %q is not usable", email)
	}
	if tenantID == "" {
		tenantID = "default"
	}
	if err := principals.EnsureTenant(ctx, tenantID, tenantID, 0, 0); err != nil {
		return "", false, fmt.Errorf("bootstrap tenant: %w", err)
	}

	principalID := tenantID + "-bootstrap-admin"
	if err := principals.Upsert(ctx, &tenancy.Principal{
		ID: principalID, TenantID: tenantID,
		Identity: email, Role: tenancy.RoleAdmin, Active: true,
	}); err != nil {
		return "", false, fmt.Errorf("bootstrap principal: %w", err)
	}

	tok, err := auth.NewInviteToken(tenantID, principalID)
	if err != nil {
		return "", false, fmt.Errorf("bootstrap token: %w", err)
	}
	if err := authRepo.CreateInvite(ctx, postgres.InviteRow{
		ID:       "inv-bootstrap-" + now().UTC().Format("20060102150405.000000000"),
		TenantID: tenantID, PrincipalID: principalID,
		SecretHash: tok.SecretHash(), CreatedBy: "system:bootstrap",
		ExpiresAt: now().Add(auth.DefaultInviteTTL),
	}); err != nil {
		return "", false, fmt.Errorf("bootstrap invite: %w", err)
	}
	return tok.Encode(), true, nil
}
