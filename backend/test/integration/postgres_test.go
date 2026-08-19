//go:build integration

package integration

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/data/postgres"
)

func dsn() string {
	if v := os.Getenv("SIEM_TEST_PG_DSN"); v != "" {
		return v
	}
	return "postgres://siem:siem_dev_only@localhost:55432/siem?sslmode=disable"
}

func TestMigrationsApplyAndAreIdempotent(t *testing.T) {
	ctx := context.Background()
	pool, err := postgres.Connect(ctx, dsn(), 5, 1)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	if err := postgres.Migrate(ctx, pool); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	// Running again must be a no-op, not an error: deployments re-run migrations
	// on every start.
	if err := postgres.Migrate(ctx, pool); err != nil {
		t.Fatalf("second migrate must be idempotent: %v", err)
	}

	for _, table := range []string{
		"tenant", "principal", "log_source", "retention_policy",
		"legal_hold", "detection", "alert", "evaluation_run", "audit_record",
	} {
		var exists bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`,
			table).Scan(&exists); err != nil {
			t.Fatalf("check %s: %v", table, err)
		}
		if !exists {
			t.Errorf("table %q was not created", table)
		}
	}
}

// TestAuditTrailIsAppendOnly is the FR-055 guarantee, tested at the database
// level rather than by trusting the application to behave.
func TestAuditTrailIsAppendOnly(t *testing.T) {
	ctx := context.Background()
	pool, err := postgres.Connect(ctx, dsn(), 5, 1)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if err := postgres.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// A tenant is required by the foreign keys elsewhere; audit_record has none
	// deliberately, so that an audit entry can never fail to record because a
	// referenced row was removed.
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenant (id, name) VALUES ('acme','Acme') ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	repo := postgres.NewAuditRepo(pool)
	if err := repo.Append(ctx, postgres.AuditEntry{
		TenantID: "acme", PrincipalID: "analyst-1",
		Action: "flow.view", Scope: "tenant:acme", TargetRef: "flow:test",
		OccurredAt: time.Now().UTC(), Outcome: "allowed",
		Detail: map[string]any{"ip": "203.0.113.9"},
	}); err != nil {
		t.Fatalf("append: %v", err)
	}

	entries, err := repo.List(ctx, "acme", 10)
	if err != nil || len(entries) == 0 {
		t.Fatalf("list: %v (%d entries)", err, len(entries))
	}

	// The actual test: an operator with full application privileges must not be
	// able to rewrite history.
	_, err = pool.Exec(ctx, `UPDATE audit_record SET outcome = 'denied' WHERE tenant_id = 'acme'`)
	if err == nil {
		t.Fatal("UPDATE on audit_record succeeded. FR-055 is not satisfied: " +
			"an operator can rewrite the audit trail.")
	}
	if !strings.Contains(err.Error(), "append-only") {
		t.Errorf("expected the append-only guard to fire, got: %v", err)
	}

	_, err = pool.Exec(ctx, `DELETE FROM audit_record WHERE tenant_id = 'acme'`)
	if err == nil {
		t.Fatal("DELETE on audit_record succeeded. Audit entries can be destroyed.")
	}

	_, err = pool.Exec(ctx, `TRUNCATE audit_record`)
	if err == nil {
		t.Fatal("TRUNCATE on audit_record succeeded, which would erase the whole trail")
	}

	// And the entry survived every attempt.
	after, err := repo.List(ctx, "acme", 10)
	if err != nil {
		t.Fatalf("list after: %v", err)
	}
	if len(after) < len(entries) {
		t.Fatal("audit entries were lost despite the guard")
	}
}
