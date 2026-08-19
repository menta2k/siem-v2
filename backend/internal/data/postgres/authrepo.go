package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuthRecord is a principal's authentication state, separate from the
// authorization-facing tenancy.Principal so credential material never rides
// along on ordinary principal loads.
type AuthRecord struct {
	PrincipalID  string
	TenantID     string
	Identity     string
	Role         string
	Active       bool
	PasswordHash string
	MFASecretEnc string
	MFAEnrolled  bool
}

// AuthRepo persists authentication state.
type AuthRepo struct{ pool *pgxpool.Pool }

func NewAuthRepo(pool *pgxpool.Pool) *AuthRepo { return &AuthRepo{pool: pool} }

// ErrNoAuthRecord is returned when an identity does not resolve. Callers
// translate it to the same coarse error as a wrong password.
var ErrNoAuthRecord = errors.New("auth record not found")

// ByEmail loads the authentication state for an identity.
//
// It returns inactive principals too: the LOGIN path must burn the same
// password-verification work for a deactivated account as for a live one, and
// only then refuse — otherwise deactivation is observable through timing.
func (r *AuthRepo) ByEmail(ctx context.Context, email string) (*AuthRecord, error) {
	var rec AuthRecord
	var pwHash, mfaEnc *string
	var enrolledAt *time.Time
	err := r.pool.QueryRow(ctx, `
		SELECT id, tenant_id, identity, role, active, password_hash, mfa_secret_enc, mfa_enrolled_at
		FROM principal WHERE identity = $1`, email).
		Scan(&rec.PrincipalID, &rec.TenantID, &rec.Identity, &rec.Role,
			&rec.Active, &pwHash, &mfaEnc, &enrolledAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoAuthRecord
		}
		return nil, fmt.Errorf("load auth record: %w", err)
	}
	if pwHash != nil {
		rec.PasswordHash = *pwHash
	}
	if mfaEnc != nil {
		rec.MFASecretEnc = *mfaEnc
	}
	rec.MFAEnrolled = enrolledAt != nil
	return &rec, nil
}

// ByID loads authentication state by principal id (token subject).
func (r *AuthRepo) ByID(ctx context.Context, principalID string) (*AuthRecord, error) {
	var rec AuthRecord
	var pwHash, mfaEnc *string
	var enrolledAt *time.Time
	err := r.pool.QueryRow(ctx, `
		SELECT id, tenant_id, identity, role, active, password_hash, mfa_secret_enc, mfa_enrolled_at
		FROM principal WHERE id = $1`, principalID).
		Scan(&rec.PrincipalID, &rec.TenantID, &rec.Identity, &rec.Role,
			&rec.Active, &pwHash, &mfaEnc, &enrolledAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoAuthRecord
		}
		return nil, fmt.Errorf("load auth record: %w", err)
	}
	if pwHash != nil {
		rec.PasswordHash = *pwHash
	}
	if mfaEnc != nil {
		rec.MFASecretEnc = *mfaEnc
	}
	rec.MFAEnrolled = enrolledAt != nil
	return &rec, nil
}

// SetPassword stores a new hash and stamps when it was set.
func (r *AuthRepo) SetPassword(ctx context.Context, principalID, phcHash string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE principal SET password_hash = $2, password_set_at = now() WHERE id = $1`,
		principalID, phcHash)
	if err != nil {
		return fmt.Errorf("set password: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNoAuthRecord
	}
	return nil
}

// SetMFASecret stores the SEALED secret WITHOUT stamping enrolment.
//
// Enrolment is confirmed only by ConfirmMFAEnrolment, after a code verifies.
// Stamping here would mean a mis-scanned QR locks the user out: the account
// would demand codes from a secret no authenticator actually holds.
func (r *AuthRepo) SetMFASecret(ctx context.Context, principalID, sealedSecret string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE principal SET mfa_secret_enc = $2, mfa_enrolled_at = NULL WHERE id = $1`,
		principalID, sealedSecret)
	if err != nil {
		return fmt.Errorf("set mfa secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNoAuthRecord
	}
	return nil
}

// ConfirmMFAEnrolment stamps enrolment once a code has proven the authenticator
// holds the secret.
func (r *AuthRepo) ConfirmMFAEnrolment(ctx context.Context, principalID string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE principal SET mfa_enrolled_at = now()
		WHERE id = $1 AND mfa_secret_enc IS NOT NULL`, principalID)
	return err
}

// RecordLogin stamps a successful login.
func (r *AuthRepo) RecordLogin(ctx context.Context, principalID string, at time.Time) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE principal SET last_login_at = $2 WHERE id = $1`, principalID, at)
	return err
}

// InviteRow is a stored invite.
type InviteRow struct {
	ID          string
	TenantID    string
	PrincipalID string
	SecretHash  string
	CreatedBy   string
	ExpiresAt   time.Time
	RedeemedAt  *time.Time
}

// CreateInvite stores a new invite, retiring any open one for the principal.
//
// The retire-then-insert runs in one transaction so there is never a moment
// with two live links: the partial unique index would reject the insert, and a
// failure between the two statements must not leave the old link dead with no
// replacement.
func (r *AuthRepo) CreateInvite(ctx context.Context, row InviteRow) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		UPDATE invite SET redeemed_at = now()
		WHERE principal_id = $1 AND redeemed_at IS NULL`, row.PrincipalID); err != nil {
		return fmt.Errorf("retire open invite: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO invite (id, tenant_id, principal_id, secret_hash, created_by, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		row.ID, row.TenantID, row.PrincipalID, row.SecretHash, row.CreatedBy, row.ExpiresAt); err != nil {
		return fmt.Errorf("create invite: %w", err)
	}
	return tx.Commit(ctx)
}

// OpenInvite loads the unredeemed invite for a principal, if any.
func (r *AuthRepo) OpenInvite(ctx context.Context, principalID string) (*InviteRow, error) {
	var row InviteRow
	err := r.pool.QueryRow(ctx, `
		SELECT id, tenant_id, principal_id, secret_hash, created_by, expires_at, redeemed_at
		FROM invite WHERE principal_id = $1 AND redeemed_at IS NULL`, principalID).
		Scan(&row.ID, &row.TenantID, &row.PrincipalID, &row.SecretHash,
			&row.CreatedBy, &row.ExpiresAt, &row.RedeemedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("load invite: %w", err)
	}
	return &row, nil
}

// RedeemInvite marks an invite spent, exactly once.
//
// The WHERE clause is the one-time guarantee: a second redemption matches zero
// rows and reports failure, whatever raced it.
func (r *AuthRepo) RedeemInvite(ctx context.Context, inviteID string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE invite SET redeemed_at = now()
		WHERE id = $1 AND redeemed_at IS NULL AND expires_at > now()`, inviteID)
	if err != nil {
		return fmt.Errorf("redeem invite: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New("invite not redeemable")
	}
	return nil
}

// AnyPasswordSet reports whether ANY active principal can sign in with a
// password. False means the deployment is effectively locked: first start, or
// a recovery situation — either way, bootstrap territory.
func (r *AuthRepo) AnyPasswordSet(ctx context.Context) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM principal
			WHERE active AND COALESCE(password_hash, '') <> ''
		)`).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("any password set: %w", err)
	}
	return exists, nil
}
