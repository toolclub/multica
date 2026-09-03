package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/multica-ai/multica/server/internal/auth"
)

type rejectingLDAPAuthenticator struct{}

func (rejectingLDAPAuthenticator) Authenticate(context.Context, string, string) (auth.LDAPIdentity, error) {
	return auth.LDAPIdentity{}, auth.ErrLDAPInvalidCredential
}

func TestPasswordLoginRejectsInvalidCredentials(t *testing.T) {
	h := &Handler{LDAPAuthenticator: rejectingLDAPAuthenticator{}}
	req := httptest.NewRequest(http.MethodPost, "/auth/password", strings.NewReader(`{"username":"alice","password":"wrong"}`))
	rec := httptest.NewRecorder()
	h.PasswordLogin(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestPasswordLoginRequiresConfiguration(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodPost, "/auth/password", strings.NewReader(`{"username":"alice","password":"secret"}`))
	rec := httptest.NewRecorder()
	h.PasswordLogin(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestLDAPIdentityEmailIsStable(t *testing.T) {
	if got := ldapIdentityEmail(auth.LDAPIdentity{Username: " Alice ", Email: " ALICE@EXAMPLE.COM "}); got != "alice@example.com" {
		t.Fatalf("mail identity = %q", got)
	}
	if got := ldapIdentityEmail(auth.LDAPIdentity{Username: " Alice "}); got != "alice@ldap.local" {
		t.Fatalf("fallback identity = %q", got)
	}
}
