package testsupport

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
)

// fakeHash is a syntactically valid PHC string that no password verifies
// against. Fixtures that never authenticate use it instead of paying argon2's
// 64 MiB cost per tenant — a suite that spends a second per fixture is a suite
// people stop running.
const fakeHash = "$argon2id$v=19$m=65536,t=1,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// NewTenant creates a tenant with one owner and returns both ids.
//
// Slugs and emails are derived from a fresh UUID so parallel tests and repeated
// runs never collide, which is why the suite needs no TRUNCATE and no
// serialisation between tests.
func NewTenant(t *testing.T, pool *pgxpool.Pool, label string) (tenantID, userID uuid.UUID) {
	t.Helper()

	suffix := strings.ReplaceAll(uuid.Must(uuid.NewV7()).String(), "-", "")[:12]
	tenantID = uuid.Must(uuid.NewV7())
	userID = uuid.Must(uuid.NewV7())

	store := tenant.NewStore(pool)
	err := store.CreateTenantWithOwner(context.Background(), tenant.Tenant{
		ID:   tenantID,
		Slug: fmt.Sprintf("%s-%s", label, suffix),
		Name: fmt.Sprintf("Test Tenant %s", label),
	}, tenant.Owner{
		ID:     userID,
		Email:  fmt.Sprintf("owner-%s@%s.test", suffix, label),
		PWHash: fakeHash,
	}, authz.RoleOwner)
	if err != nil {
		t.Fatalf("testsupport: create tenant %s: %v", label, err)
	}
	return tenantID, userID
}

// AddUser creates a user (with no membership) and returns its id.
func AddUser(t *testing.T, pool *pgxpool.Pool, label string) uuid.UUID {
	t.Helper()

	id := uuid.Must(uuid.NewV7())
	suffix := strings.ReplaceAll(uuid.Must(uuid.NewV7()).String(), "-", "")[:12]
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, email, pw_hash) VALUES ($1, $2, $3)`,
		id, fmt.Sprintf("member-%s@%s.test", suffix, label), fakeHash)
	if err != nil {
		t.Fatalf("testsupport: create user %s: %v", label, err)
	}
	return id
}
